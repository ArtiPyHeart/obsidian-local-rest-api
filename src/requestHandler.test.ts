import http from "http";
import request from "supertest";

import RequestHandler from "./requestHandler";
import { LocalRestApiSettings } from "./types";
import { CERT_NAME } from "./constants";
import {
  App,
  TFile,
  Command,
  HeadingCache,
  PluginManifest,
} from "../mocks/obsidian";

describe("requestHandler", () => {
  const API_KEY = "my api key";

  let settings: LocalRestApiSettings;
  let app: App;
  let manifest: PluginManifest;
  let handler: RequestHandler;
  let server: http.Server;

  beforeEach(() => {
    settings = getMockSettings();
    // This 'App' instance is actually a mock, and it doesn't define
    // quite a perfectly-matching interface for the actual Obsidian
    // App interface.
    app = new App();
    manifest = new PluginManifest();
    // @ts-ignore: Ignore missing App properties
    handler = new RequestHandler(app, manifest, settings);
    handler.setupRouter();
    server = http.createServer(handler.api);
  });

  afterEach(() => {
    server.close();
  });

  function getMockSettings(): LocalRestApiSettings {
    return {
      apiKey: API_KEY,
      crypto: {
        cert: "cert",
        privateKey: "privateKey",
        publicKey: "publicKey",
      },
      port: 1,
      insecurePort: 2,
      enableInsecureServer: false,
    };
  }
  describe("requestIsAuthenticated", () => {
    const arbitraryAuthenticatedRoute = "/vault/";

    test("missing header", async () => {
      await request(server).get(arbitraryAuthenticatedRoute).expect(401);
    });
    test("incorrect header", async () => {
      await request(server)
        .get(arbitraryAuthenticatedRoute)
        .set("Authorization", "Bearer of good tidings")
        .expect(401);
    });
    test("correct header", async () => {
      await request(server)
        .get(arbitraryAuthenticatedRoute)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);
    });
  });

  describe("root", () => {
    test("withhout auth", async () => {
      const result = await request(server).get("/").expect(200);

      expect(result.body.status).toEqual("OK");
      expect(result.body.authenticated).toBeFalsy();
    });

    test("with auth", async () => {
      const result = await request(server)
        .get("/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.body.status).toEqual("OK");
      expect(result.body.authenticated).toBeTruthy();
    });
  });

  describe("certificateGet", () => {
    const certPath = `/${CERT_NAME}`;

    test("withhout auth", async () => {
      const result = await request(server).get(certPath).expect(200);

      expect(result.body.toString()).toEqual(settings.crypto?.cert);
    });

    test("with auth", async () => {
      const result = await request(server)
        .get(certPath)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.body.toString()).toEqual(settings.crypto.cert);
    });
  });

  describe("vaultGet", () => {
    test("directory empty", async () => {
      app.vault._files = [];

      await request(server)
        .get("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(404);
    });

    test("directory with files", async () => {
      const arbitraryDirectory = "somewhere";

      const rootFile = new TFile();
      rootFile.path = "rootFile.md";

      const notRootFile = new TFile();
      notRootFile.path = `${arbitraryDirectory}/anotherFile.md`;

      app.vault._files = [rootFile, notRootFile];

      const result = await request(server)
        .get("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.body.files).toEqual([
        rootFile.path,
        `${arbitraryDirectory}/`,
      ]);
    });

    test("unauthorized", async () => {
      const arbitraryFilename = "somefile.md";
      const arbitraryFileContent = "Beep boop";

      app.vault.adapter._read = arbitraryFileContent;

      await request(server).get(`/vault/${arbitraryFilename}`).expect(401);
    });

    test("file content", async () => {
      const arbitraryFilename = "somefile.md";
      const arbitraryFileContent = "Beep boop";
      const fileContentBuffer = new ArrayBuffer(arbitraryFileContent.length);
      const fileContentBufferView = new Uint8Array(fileContentBuffer);
      for (let i = 0; i < arbitraryFileContent.length; i++) {
        fileContentBufferView[i] = arbitraryFileContent.charCodeAt(i);
      }

      app.vault.adapter._readBinary = fileContentBuffer;

      const result = await request(server)
        .get(`/vault/${arbitraryFilename}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.header["content-disposition"]).toEqual(
        `attachment; filename="${arbitraryFilename}"`
      );
      expect(result.header["content-type"]).toEqual(
        "text/markdown; charset=utf-8"
      );
      expect(result.text).toEqual(arbitraryFileContent);
    });

    test("file does not exist", async () => {
      const arbitraryFilename = "somefile.md";

      app.vault.adapter._exists = false;

      await request(server)
        .get(`/vault/${arbitraryFilename}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(404);
    });
  });

  describe("vaultPut", () => {
    test("directory", async () => {
      await request(server)
        .put("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(405);
    });

    test("unauthorized", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .put(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .send(arbitraryBytes)
        .expect(401);
    });

    test("acceptable content", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .put(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(204);

      expect(app.vault.adapter._write).toEqual([
        arbitraryFilePath,
        arbitraryBytes,
      ]);
    });

    test("acceptable binary content", async () => {
      const arbitraryFilePath = "test.png";
      const arbitraryBytes = "bytes"; // mock a picture binary

      await request(server)
        .put(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "image/jpeg")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(204);

      expect(app.vault.adapter._writeBinary[0]).toEqual(arbitraryFilePath);
      const data = app.vault.adapter._writeBinary[1];
      expect(Buffer.isBuffer(data) || data instanceof ArrayBuffer).toEqual(
        true
      );
      // We won't be able to convert the incoming data
      // to bytes with this mechanism in a _normal_
      // situation because those bytes won't be encodable
      // as ASCII, but we can do this here because we're
      // lying about the incoming content type above
      const decoder = new TextDecoder();
      expect(decoder.decode(data)).toEqual(arbitraryBytes);
    });

    test("non-bytes content", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .put(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(400);

      expect(app.vault.adapter._write).toBeUndefined();
    });
  });

  describe("vaultPost", () => {
    test("directory", async () => {
      await request(server)
        .post("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(405);
    });

    test("unauthorized", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      const arbitraryExistingBytes = "something\nsomething\n";

      app.vault._read = arbitraryExistingBytes;

      await request(server)
        .post(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .send(arbitraryBytes)
        .expect(401);
    });

    describe("acceptable content", () => {
      test("existing with trailing newline", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";

        const arbitraryExistingBytes = "something\nsomething\n";

        app.vault._read = arbitraryExistingBytes;

        await request(server)
          .post(`/vault/${arbitraryFilePath}`)
          .set("Content-Type", "text/markdown")
          .set("Authorization", `Bearer ${API_KEY}`)
          .send(arbitraryBytes)
          .expect(204);

        expect(app.vault.adapter._write).toEqual([
          arbitraryFilePath,
          arbitraryExistingBytes + arbitraryBytes,
        ]);
      });

      test("existing without trailing newline", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";

        const arbitraryExistingBytes = "something\nsomething";

        app.vault._read = arbitraryExistingBytes;

        await request(server)
          .post(`/vault/${arbitraryFilePath}`)
          .set("Content-Type", "text/markdown")
          .set("Authorization", `Bearer ${API_KEY}`)
          .send(arbitraryBytes)
          .expect(204);

        expect(app.vault.adapter._write).toEqual([
          arbitraryFilePath,
          arbitraryExistingBytes + "\n" + arbitraryBytes,
        ]);
      });
    });

    test("non-bytes content", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .post(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "application/json")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(400);

      expect(app.vault.adapter._write).toBeUndefined();
    });
  });

  describe("vaultDelete", () => {
    test("directory", async () => {
      await request(server)
        .delete("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(405);
    });

    test("non-existing file", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      app.vault.adapter._exists = false;

      await request(server)
        .delete(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(404);

      expect(app.vault.adapter._remove).toBeUndefined();
    });

    test("unauthorized", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .delete(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .send(arbitraryBytes)
        .expect(401);
    });

    test("existing file", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";

      await request(server)
        .delete(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .set("Authorization", `Bearer ${API_KEY}`)
        .send(arbitraryBytes)
        .expect(204);

      expect(app.vault.adapter._remove).toEqual([arbitraryFilePath]);
    });
  });

  describe("vaultPatch", () => {
    test("directory", async () => {
      await request(server)
        .patch("/vault/")
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(405);
    });

    test("missing heading header", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";
      const arbitraryHeading = "somewhere";

      const arbitraryExistingBytes = "something\nsomething";

      const headingCache = new HeadingCache();
      headingCache.heading = arbitraryHeading;

      app.vault._read = arbitraryExistingBytes;
      app.metadataCache._getFileCache.headings.push(headingCache);

      await request(server)
        .patch(`/vault/${arbitraryFilePath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "text/markdown")
        .send(arbitraryBytes)
        .expect(400);
    });

    test("non-bytes content", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";
      const arbitraryHeading = "somewhere";

      const arbitraryExistingBytes = "something\nsomething";

      const headingCache = new HeadingCache();
      headingCache.heading = arbitraryHeading;

      app.vault._read = arbitraryExistingBytes;
      app.metadataCache._getFileCache.headings.push(headingCache);

      await request(server)
        .patch(`/vault/${arbitraryFilePath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Heading", arbitraryHeading)
        .send(arbitraryBytes)
        .expect(400);
    });

    test("non-existing file", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";
      const arbitraryHeading = "somewhere";

      const arbitraryExistingBytes = "something\nsomething";

      const headingCache = new HeadingCache();
      headingCache.heading = arbitraryHeading;

      app.vault._read = arbitraryExistingBytes;
      app.metadataCache._getFileCache.headings.push(headingCache);
      app.vault._getAbstractFileByPath = null;

      await request(server)
        .patch(`/vault/${arbitraryFilePath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "text/markdown")
        .set("Heading", arbitraryHeading)
        .send(arbitraryBytes)
        .expect(404);
    });

    test("unauthorized", async () => {
      const arbitraryFilePath = "somefile.md";
      const arbitraryBytes = "bytes";
      const arbitraryHeading = "somewhere";

      const arbitraryExistingBytes = "something\nsomething";

      const headingCache = new HeadingCache();
      headingCache.heading = arbitraryHeading;

      app.vault._read = arbitraryExistingBytes;
      app.metadataCache._getFileCache.headings.push(headingCache);

      await request(server)
        .patch(`/vault/${arbitraryFilePath}`)
        .set("Content-Type", "text/markdown")
        .set("Heading", arbitraryHeading)
        .set("Content-Insertion-Position", "beginning")
        .send(arbitraryBytes)
        .expect(401);
    });

    describe("acceptable content", () => {
      // Unfortunately, testing the actual written content would be
      // extremely brittle given that we're relying on private Obsidian
      // API interfaces; so we're just going to verify that we get
      // a 200 and that a write occurs :shrug:

      test("undefined content-insertion-position", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "somewhere";

        const arbitraryExistingBytes = "something\nsomething";

        const headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        app.vault._read = arbitraryExistingBytes;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
      });

      test("beginning content-insertion-position", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "somewhere";

        const arbitraryExistingBytes = "something\nsomething";

        const headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        app.vault._read = arbitraryExistingBytes;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "beginning")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual("bytes\nsomething\nsomething");
      });

      test("end content-insertion-position", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "somewhere";

        const arbitraryExistingBytes = "something\nsomething";

        const headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        app.vault._read = arbitraryExistingBytes;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "end")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual("something\nsomething\nbytes");
      });

      test("beginning content-insertion-position with header", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "Heading1";

        const arbitraryExistingBytes =
          "something\n\n# Heading1\ncontent here\n# Heading2\nsomething";
        app.vault._read = arbitraryExistingBytes;

        // Heading 1
        let headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        headingCache.position.end.line = 2;
        headingCache.position.start.line = 2;
        app.metadataCache._getFileCache.headings.push(headingCache);

        // Heading 2
        headingCache = new HeadingCache();
        headingCache.heading = "Heading2";

        headingCache.position.end.line = 4;
        headingCache.position.start.line = 4;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "beginning")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual(
          "something\n\n# Heading1\nbytes\ncontent here\n# Heading2\nsomething"
        );
      });

      test("end content-insertion-position with header", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "Heading1";

        const arbitraryExistingBytes =
          "something\n\n# Heading1\ncontent here\n# Heading2\nsomething";
        app.vault._read = arbitraryExistingBytes;

        // Heading 1
        let headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        headingCache.position.end.line = 2;
        headingCache.position.start.line = 2;
        app.metadataCache._getFileCache.headings.push(headingCache);

        // Heading 2
        headingCache = new HeadingCache();
        headingCache.heading = "Heading2";

        headingCache.position.end.line = 4;
        headingCache.position.start.line = 4;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "end")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual(
          "something\n\n# Heading1\ncontent here\nbytes\n# Heading2\nsomething"
        );
      });

      test("end content-insertion-position with header (new lines at end of header block)", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "Heading1";

        const arbitraryExistingBytes =
          "something\n\n# Heading1\ncontent here\n\n\n# Heading2\nsomething";
        app.vault._read = arbitraryExistingBytes;

        // Heading 1
        let headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        headingCache.position.end.line = 2;
        headingCache.position.start.line = 2;
        app.metadataCache._getFileCache.headings.push(headingCache);

        // Heading 2
        headingCache = new HeadingCache();
        headingCache.heading = "Heading2";

        headingCache.position.end.line = 6;
        headingCache.position.start.line = 6;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "end")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual(
          "something\n\n# Heading1\ncontent here\n\n\nbytes\n# Heading2\nsomething"
        );
      });

      test("end content-insertion-position with header ignore newlines", async () => {
        const arbitraryFilePath = "somefile.md";
        const arbitraryBytes = "bytes";
        const arbitraryHeading = "Heading1";

        const arbitraryExistingBytes =
          "something\n\n# Heading1\ncontent here\n\n\n# Heading2\nsomething";
        app.vault._read = arbitraryExistingBytes;

        // Heading 1
        let headingCache = new HeadingCache();
        headingCache.heading = arbitraryHeading;

        headingCache.position.end.line = 2;
        headingCache.position.start.line = 2;
        app.metadataCache._getFileCache.headings.push(headingCache);

        // Heading 2
        headingCache = new HeadingCache();
        headingCache.heading = "Heading2";

        headingCache.position.end.line = 6;
        headingCache.position.start.line = 6;
        app.metadataCache._getFileCache.headings.push(headingCache);

        const result = await request(server)
          .patch(`/vault/${arbitraryFilePath}`)
          .set("Authorization", `Bearer ${API_KEY}`)
          .set("Content-Type", "text/markdown")
          .set("Heading", arbitraryHeading)
          .set("Content-Insertion-Position", "end")
          .set("Content-Insertion-Ignore-Newline", "true")
          .send(arbitraryBytes)
          .expect(200);

        expect(app.vault.adapter.write).toBeTruthy();
        expect(result.text).toBeTruthy();
        expect(result.text).toEqual(
          "something\n\n# Heading1\ncontent here\nbytes\n\n\n# Heading2\nsomething"
        );
      });
    });
  });

  describe("commandGet", () => {
    test("acceptable", async () => {
      const arbitraryCommand = new Command();
      arbitraryCommand.id = "beep";
      arbitraryCommand.name = "boop";

      app.commands.commands[arbitraryCommand.id] = arbitraryCommand;

      const result = await request(server)
        .get(`/commands/`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.body.commands).toEqual([
        {
          id: arbitraryCommand.id,
          name: arbitraryCommand.name,
        },
      ]);
    });

    test("unauthorized", async () => {
      const arbitraryCommand = new Command();
      arbitraryCommand.id = "beep";
      arbitraryCommand.name = "boop";

      app.commands.commands[arbitraryCommand.id] = arbitraryCommand;

      await request(server).get(`/commands/`).expect(401);
    });
  });

  describe("commandPost", () => {
    test("acceptable", async () => {
      const arbitraryCommand = new Command();
      arbitraryCommand.id = "beep";
      arbitraryCommand.name = "boop";

      app.commands.commands[arbitraryCommand.id] = arbitraryCommand;

      await request(server)
        .post(`/commands/${arbitraryCommand.id}/`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(204);

      expect(app._executeCommandById).toEqual([arbitraryCommand.id]);
    });

    test("unauthorized", async () => {
      const arbitraryCommand = new Command();
      arbitraryCommand.id = "beep";
      arbitraryCommand.name = "boop";

      app.commands.commands[arbitraryCommand.id] = arbitraryCommand;

      await request(server)
        .post(`/commands/${arbitraryCommand.id}`)
        .expect(401);
    });
  });

  describe("canvasGet", () => {
    test("file content", async () => {
      const canvasPath = "test.canvas";
      const canvasData = JSON.stringify({
        nodes: [{ id: "n1", type: "text", x: 0, y: 0, width: 200, height: 100, text: "Hello" }],
        edges: [] as unknown[],
      });
      const fileContentBuffer = new ArrayBuffer(canvasData.length);
      const fileContentBufferView = new Uint8Array(fileContentBuffer);
      for (let i = 0; i < canvasData.length; i++) {
        fileContentBufferView[i] = canvasData.charCodeAt(i);
      }

      app.vault.adapter._readBinary = fileContentBuffer;

      const result = await request(server)
        .get(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .expect(200);

      expect(result.header["content-type"]).toContain("application/json");
      const body = JSON.parse(result.text);
      expect(body.nodes).toHaveLength(1);
      expect(body.nodes[0].type).toEqual("text");
    });

    test("canvas with metadata accept header", async () => {
      const canvasPath = "test.canvas";
      const canvasData = JSON.stringify({
        nodes: [
          { id: "n1", type: "text", x: 0, y: 0, width: 200, height: 100, text: "Hello" },
          { id: "n2", type: "file", x: 300, y: 0, width: 200, height: 100, file: "test.md" },
        ],
        edges: [{ id: "e1", fromNode: "n1", toNode: "n2" }],
      });

      const canvasFile = new TFile();
      canvasFile.path = canvasPath;
      app.vault._getAbstractFileByPath = canvasFile;
      app.vault._cachedRead = canvasData;

      const result = await request(server)
        .get(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Accept", "application/vnd.olrapi.canvas+json")
        .expect(200);

      expect(result.body.canvas).toBeDefined();
      expect(result.body.metadata).toBeDefined();
      expect(result.body.metadata.nodeCount).toEqual(2);
      expect(result.body.metadata.edgeCount).toEqual(1);
      expect(result.body.metadata.nodeTypes.text).toEqual(1);
      expect(result.body.metadata.nodeTypes.file).toEqual(1);
      expect(result.body.metadata.referencedFiles).toContain("test.md");
    });
  });

  describe("canvasPut", () => {
    test("valid canvas structure", async () => {
      const canvasPath = "test.canvas";
      const canvasData = {
        nodes: [{ id: "n1", type: "text", x: 0, y: 0, width: 200, height: 100, text: "Hello" }],
        edges: [] as unknown[],
      };

      await request(server)
        .put(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/json")
        .send(canvasData)
        .expect(204);

      expect(app.vault.adapter._write[0]).toEqual(canvasPath);
    });

    test("invalid canvas structure - missing node id", async () => {
      const canvasPath = "test.canvas";
      const canvasData = {
        nodes: [{ type: "text", x: 0, y: 0, width: 200, height: 100, text: "Hello" }],
        edges: [] as unknown[],
      };

      await request(server)
        .put(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/json")
        .send(canvasData)
        .expect(400);
    });

    test("invalid canvas structure - invalid node type", async () => {
      const canvasPath = "test.canvas";
      const canvasData = {
        nodes: [{ id: "n1", type: "invalid", x: 0, y: 0, width: 200, height: 100 }],
        edges: [] as unknown[],
      };

      await request(server)
        .put(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/json")
        .send(canvasData)
        .expect(400);
    });
  });

  describe("canvasPatch", () => {
    const validCanvas = {
      nodes: [
        { id: "n1", type: "text", x: 0, y: 0, width: 200, height: 100, text: "Hello" },
        { id: "n2", type: "text", x: 300, y: 0, width: 200, height: 100, text: "World" },
      ],
      edges: [{ id: "e1", fromNode: "n1", toNode: "n2" }],
    };

    beforeEach(() => {
      const canvasFile = new TFile();
      canvasFile.path = "test.canvas";
      app.vault._getAbstractFileByPath = canvasFile;
      app.vault._read = JSON.stringify(validCanvas);
    });

    test("add node", async () => {
      const canvasPath = "test.canvas";
      const newNode = { id: "n3", type: "text", x: 600, y: 0, width: 200, height: 100, text: "New" };

      const result = await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "node")
        .set("Operation", "add")
        .send(newNode)
        .expect(200);

      expect(result.body.nodes).toHaveLength(3);
      expect(result.body.nodes.some((n: any) => n.id === "n3")).toBe(true);
    });

    test("update node", async () => {
      const canvasPath = "test.canvas";
      const updateData = { text: "Updated" };

      const result = await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "node")
        .set("Operation", "update")
        .set("Target", "n1")
        .send(updateData)
        .expect(200);

      const updatedNode = result.body.nodes.find((n: any) => n.id === "n1");
      expect(updatedNode.text).toEqual("Updated");
    });

    test("delete node", async () => {
      const canvasPath = "test.canvas";

      const result = await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "node")
        .set("Operation", "delete")
        .set("Target", "n1")
        .send({})
        .expect(200);

      expect(result.body.nodes).toHaveLength(1);
      expect(result.body.nodes.some((n: any) => n.id === "n1")).toBe(false);
      // Edge referencing deleted node should also be removed
      expect(result.body.edges).toHaveLength(0);
    });

    test("add edge", async () => {
      const canvasPath = "test.canvas";
      const newEdge = { id: "e2", fromNode: "n2", toNode: "n1" };

      const result = await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "edge")
        .set("Operation", "add")
        .send(newEdge)
        .expect(200);

      expect(result.body.edges).toHaveLength(2);
    });

    test("batch operations on nodes", async () => {
      const canvasPath = "test.canvas";
      const batchOps = {
        add: [{ id: "n3", type: "text", x: 600, y: 0, width: 200, height: 100, text: "New" }],
        update: { n1: { text: "Updated" } },
        delete: ["n2"],
      };

      const result = await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "nodes")
        .send(batchOps)
        .expect(200);

      // Should have n1 (updated) and n3 (added), but not n2 (deleted)
      expect(result.body.nodes).toHaveLength(2);
      expect(result.body.nodes.some((n: any) => n.id === "n1" && n.text === "Updated")).toBe(true);
      expect(result.body.nodes.some((n: any) => n.id === "n3")).toBe(true);
      expect(result.body.nodes.some((n: any) => n.id === "n2")).toBe(false);
    });

    test("error - node id conflict", async () => {
      const canvasPath = "test.canvas";
      const duplicateNode = { id: "n1", type: "text", x: 600, y: 0, width: 200, height: 100, text: "Dup" };

      await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "node")
        .set("Operation", "add")
        .send(duplicateNode)
        .expect(409);
    });

    test("error - node not found for update", async () => {
      const canvasPath = "test.canvas";

      await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "node")
        .set("Operation", "update")
        .set("Target", "nonexistent")
        .send({ text: "Updated" })
        .expect(404);
    });

    test("error - invalid target type", async () => {
      const canvasPath = "test.canvas";

      await request(server)
        .patch(`/vault/${canvasPath}`)
        .set("Authorization", `Bearer ${API_KEY}`)
        .set("Content-Type", "application/vnd.olrapi.canvas.patch+json")
        .set("Target-Type", "invalid")
        .set("Operation", "add")
        .send({})
        .expect(400);
    });
  });
});
