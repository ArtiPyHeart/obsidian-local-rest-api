import {
  apiVersion,
  App,
  CachedMetadata,
  Command,
  PluginManifest,
  prepareSimpleSearch,
  TFile,
} from "obsidian";
import periodicNotes from "obsidian-daily-notes-interface";
import { getAPI as getDataviewAPI } from "obsidian-dataview";
import forge from "node-forge";

import express from "express";
import http from "http";
import cors from "cors";
import mime from "mime-types";
import bodyParser from "body-parser";
import jsonLogic from "json-logic-js";
import responseTime from "response-time";
import queryString from "query-string";
import WildcardRegexp from "glob-to-regexp";
import path from "path";
import {
  applyPatch,
  ContentType,
  PatchFailed,
  PatchInstruction,
  PatchOperation,
  PatchTargetType,
} from "markdown-patch";

import {
  CannedResponse,
  CanvasBatchPatch,
  CanvasData,
  CanvasEdge,
  CanvasMetadataObject,
  CanvasNode,
  CanvasPatchOperation,
  CanvasPatchTargetType,
  CanvasSearchContext,
  CanvasSearchResponseItem,
  ErrorCode,
  ErrorResponseDescriptor,
  FileMetadataObject,
  LocalRestApiSettings,
  PeriodicNoteInterface,
  SearchContext,
  SearchJsonResponseItem,
  SearchResponseItem,
} from "./types";
import {
  findHeadingBoundary,
  getCertificateIsUptoStandards,
  getCertificateValidityDays,
  getSplicePosition,
  toArrayBuffer,
} from "./utils";
import {
  getCanvasMetadata,
  getTextFromCanvasNodes,
  isCanvasFile,
  parseCanvasData,
  validateCanvasEdge,
  validateCanvasNode,
  validateCanvasStructure,
} from "./canvasUtils";
import {
  CERT_NAME,
  ContentTypes,
  ERROR_CODE_MESSAGES,
  MaximumRequestSize,
} from "./constants";
import LocalRestApiPublicApi from "./api";

// Import openapi.yaml as a string
import openapiYaml from "../docs/openapi.yaml";

export default class RequestHandler {
  app: App;
  api: express.Express;
  manifest: PluginManifest;
  settings: LocalRestApiSettings;

  apiExtensionRouter: express.Router;
  apiExtensions: {
    manifest: PluginManifest;
    api: LocalRestApiPublicApi;
  }[] = [];

  constructor(
    app: App,
    manifest: PluginManifest,
    settings: LocalRestApiSettings
  ) {
    this.app = app;
    this.manifest = manifest;
    this.api = express();
    this.settings = settings;

    this.apiExtensionRouter = express.Router();

    this.api.set("json spaces", 2);

    jsonLogic.add_operation(
      "glob",
      (pattern: string | undefined, field: string | undefined) => {
        if (typeof field === "string" && typeof pattern === "string") {
          const glob = WildcardRegexp(pattern);
          return glob.test(field);
        }
        return false;
      }
    );
    jsonLogic.add_operation(
      "regexp",
      (pattern: string | undefined, field: string | undefined) => {
        if (typeof field === "string" && typeof pattern === "string") {
          const rex = new RegExp(pattern);
          return rex.test(field);
        }
        return false;
      }
    );
  }

  registerApiExtension(manifest: PluginManifest): LocalRestApiPublicApi {
    let api: LocalRestApiPublicApi | undefined = undefined;
    for (const { manifest: existingManifest, api: existingApi } of this
      .apiExtensions) {
      if (JSON.stringify(existingManifest) === JSON.stringify(manifest)) {
        api = existingApi;
        break;
      }
    }
    if (!api) {
      const router = express.Router();
      this.apiExtensionRouter.use(router);
      api = new LocalRestApiPublicApi(router, () => {
        const idx = this.apiExtensions.findIndex(
          ({ manifest: storedManifest }) =>
            JSON.stringify(manifest) === JSON.stringify(storedManifest)
        );
        if (idx !== -1) {
          this.apiExtensions.splice(idx, 1);
          this.apiExtensionRouter.stack.splice(idx, 1);
        }
      });
      this.apiExtensions.push({
        manifest,
        api,
      });
    }

    return api;
  }

  requestIsAuthenticated(req: express.Request): boolean {
    const authorizationHeader = req.get(
      this.settings.authorizationHeaderName ?? "Authorization"
    );
    if (authorizationHeader === `Bearer ${this.settings.apiKey}`) {
      return true;
    }

    return false;
  }

  async authenticationMiddleware(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void> {
    const authenticationExemptRoutes: string[] = [
      "/",
      `/${CERT_NAME}`,
      "/openapi.yaml",
    ];

    if (
      !authenticationExemptRoutes.includes(req.path) &&
      !this.requestIsAuthenticated(req)
    ) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.ApiKeyAuthorizationRequired,
      });
      return;
    }

    next();
  }

  async getFileMetadataObject(file: TFile): Promise<FileMetadataObject> {
    const cache = this.app.metadataCache.getFileCache(file);

    // Gather frontmatter & strip out positioning information
    const frontmatter = { ...(cache.frontmatter ?? {}) };
    delete frontmatter.position; // This just adds noise

    // Gather both in-line tags (hash'd) & frontmatter tags; strip
    // leading '#' from them if it's there, and remove duplicates
    const directTags =
      (cache.tags ?? []).filter((tag) => tag).map((tag) => tag.tag) ?? [];
    const frontmatterTags = Array.isArray(frontmatter.tags)
      ? frontmatter.tags
      : [];
    const filteredTags: string[] = [...frontmatterTags, ...directTags]
      // Filter out falsy tags
      .filter((tag) => tag)
      // Strip leading hash and get tag's string representation --
      // although it should always be a string, it apparently isn't always!
      .map((tag) => tag.toString().replace(/^#/, ""))
      // Remove duplicates
      .filter((value, index, self) => self.indexOf(value) === index);

    return {
      tags: filteredTags,
      frontmatter: frontmatter,
      stat: file.stat,
      path: file.path,
      content: await this.app.vault.cachedRead(file),
    };
  }

  async getCanvasMetadataObject(file: TFile): Promise<CanvasMetadataObject> {
    const content = await this.app.vault.cachedRead(file);
    const canvas = parseCanvasData(content);
    return getCanvasMetadata(canvas, file.path, file.stat);
  }

  getResponseMessage({
    statusCode = 400,
    message,
    errorCode,
  }: ErrorResponseDescriptor): string {
    const errorMessages: string[] = [];
    if (errorCode) {
      errorMessages.push(ERROR_CODE_MESSAGES[errorCode]);
    } else {
      errorMessages.push(http.STATUS_CODES[statusCode]);
    }
    if (message) {
      errorMessages.push(message);
    }

    return errorMessages.join("\n");
  }

  getStatusCode({ statusCode, errorCode }: ErrorResponseDescriptor): number {
    if (statusCode) {
      return statusCode;
    }
    return Math.floor(errorCode / 100);
  }

  returnCannedResponse(
    res: express.Response,
    { statusCode, message, errorCode }: ErrorResponseDescriptor
  ): void {
    const response: CannedResponse = {
      message: this.getResponseMessage({ statusCode, message, errorCode }),
      errorCode: errorCode ?? statusCode * 100,
    };

    res.status(this.getStatusCode({ statusCode, errorCode })).json(response);
  }

  root(req: express.Request, res: express.Response): void {
    let certificate: forge.pki.Certificate | undefined;
    try {
      certificate = forge.pki.certificateFromPem(this.settings.crypto.cert);
    } catch (e) {
      // This is fine, we just won't include that in the output
    }

    res.status(200).json({
      status: "OK",
      manifest: this.manifest,
      versions: {
        obsidian: apiVersion,
        self: this.manifest.version,
      },
      service: "Obsidian Local REST API",
      authenticated: this.requestIsAuthenticated(req),
      certificateInfo:
        this.requestIsAuthenticated(req) && certificate
          ? {
              validityDays: getCertificateValidityDays(certificate),
              regenerateRecommended:
                !getCertificateIsUptoStandards(certificate),
            }
          : undefined,
      apiExtensions: this.requestIsAuthenticated(req)
        ? this.apiExtensions.map(({ manifest }) => manifest)
        : undefined,
    });
  }

  async _vaultGet(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    if (!path || path.endsWith("/")) {
      const files = [
        ...new Set(
          this.app.vault
            .getFiles()
            .map((e) => e.path)
            .filter((filename) => filename.startsWith(path))
            .map((filename) => {
              const subPath = filename.slice(path.length);
              if (subPath.indexOf("/") > -1) {
                return subPath.slice(0, subPath.indexOf("/") + 1);
              }
              return subPath;
            })
        ),
      ];
      files.sort();

      if (files.length === 0) {
        this.returnCannedResponse(res, { statusCode: 404 });
        return;
      }

      res.json({
        files: files,
      });
    } else {
      const exists = await this.app.vault.adapter.exists(path);

      if (exists && (await this.app.vault.adapter.stat(path)).type === "file") {
        const content = await this.app.vault.adapter.readBinary(path);
        let mimeType: string | false = mime.lookup(path);

        // Default canvas files to application/json
        if (!mimeType && isCanvasFile(path)) {
          mimeType = "application/json";
        }

        res.set({
          "Content-Disposition": `attachment; filename="${encodeURI(
            path
          ).replace(",", "%2C")}"`,
          "Content-Type":
            `${mimeType || "application/octet-stream"}` +
            (mimeType == ContentTypes.markdown ? "; charset=utf-8" : ""),
        });

        if (req.headers.accept === ContentTypes.olrapiNoteJson) {
          const file = this.app.vault.getAbstractFileByPath(path) as TFile;
          res.setHeader("Content-Type", ContentTypes.olrapiNoteJson);
          res.send(
            JSON.stringify(await this.getFileMetadataObject(file), null, 2)
          );
          return;
        }

        // Handle canvas files with metadata
        if (
          isCanvasFile(path) &&
          req.headers.accept === ContentTypes.canvasJson
        ) {
          const file = this.app.vault.getAbstractFileByPath(path) as TFile;
          try {
            const metadata = await this.getCanvasMetadataObject(file);
            res.setHeader("Content-Type", ContentTypes.canvasJson);
            res.send(JSON.stringify(metadata, null, 2));
          } catch (e) {
            this.returnCannedResponse(res, {
              errorCode: ErrorCode.InvalidCanvasFormat,
              message: e.message,
            });
          }
          return;
        }

        res.send(Buffer.from(content));
      } else {
        this.returnCannedResponse(res, {
          statusCode: 404,
        });
        return;
      }
    }
  }

  async vaultGet(req: express.Request, res: express.Response): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    return this._vaultGet(path, req, res);
  }

  async _vaultPut(
    filepath: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    if (!filepath || filepath.endsWith("/")) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.RequestMethodValidOnlyForFiles,
      });
      return;
    }

    try {
      await this.app.vault.createFolder(path.dirname(filepath));
    } catch {
      // the folder/file already exists, but we don't care
    }

    // Handle canvas files with JSON validation
    if (isCanvasFile(filepath) && typeof req.body === "object") {
      try {
        validateCanvasStructure(req.body);
        await this.app.vault.adapter.write(
          filepath,
          JSON.stringify(req.body, null, 2)
        );
        this.returnCannedResponse(res, { statusCode: 204 });
        return;
      } catch (e) {
        this.returnCannedResponse(res, {
          errorCode: ErrorCode.InvalidCanvasFormat,
          message: e.message,
        });
        return;
      }
    }

    if (typeof req.body === "string") {
      await this.app.vault.adapter.write(filepath, req.body);
    } else {
      await this.app.vault.adapter.writeBinary(
        filepath,
        toArrayBuffer(req.body)
      );
    }

    this.returnCannedResponse(res, { statusCode: 204 });
    return;
  }

  async vaultPut(req: express.Request, res: express.Response): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    return this._vaultPut(path, req, res);
  }

  async _vaultPatchV2(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const headingBoundary = req.get("Heading-Boundary") || "::";
    const heading = (req.get("Heading") || "")
      .split(headingBoundary)
      .filter(Boolean);
    const contentPosition = req.get("Content-Insertion-Position");
    let insert = false;
    let aboveNewLine = false;

    if (contentPosition === undefined) {
      insert = false;
    } else if (contentPosition === "beginning") {
      insert = true;
    } else if (contentPosition === "end") {
      insert = false;
    } else {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidContentInsertionPositionValue,
      });
      return;
    }
    if (typeof req.body != "string") {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.TextContentEncodingRequired,
      });
      return;
    }

    if (typeof req.get("Content-Insertion-Ignore-Newline") == "string") {
      aboveNewLine =
        req.get("Content-Insertion-Ignore-Newline").toLowerCase() == "true";
    }

    if (!heading.length) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.MissingHeadingHeader,
      });
      return;
    }

    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) {
      this.returnCannedResponse(res, {
        statusCode: 404,
      });
      return;
    }
    const cache = this.app.metadataCache.getFileCache(file);
    const position = findHeadingBoundary(cache, heading);

    if (!position) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidHeadingHeader,
      });
      return;
    }

    const fileContents = await this.app.vault.read(file);
    const fileLines = fileContents.split("\n");

    const splicePosition = getSplicePosition(
      fileLines,
      position,
      insert,
      aboveNewLine
    );

    fileLines.splice(splicePosition, 0, req.body);

    const content = fileLines.join("\n");

    await this.app.vault.adapter.write(path, content);

    console.warn(
      `2.x PATCH implementation is deprecated and will be removed in version 4.0`
    );
    res
      .header("Deprecation", 'true; sunset-version="4.0"')
      .header(
        "Link",
        '<https://github.com/coddingtonbear/obsidian-local-rest-api/wiki/Changes-to-PATCH-requests-between-versions-2.0-and-3.0>; rel="alternate"'
      )
      .status(200)
      .send(content);
  }

  async _vaultPatchV3(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const operation = req.get("Operation");
    const targetType = req.get("Target-Type");
    const rawTarget = decodeURIComponent(req.get("Target"));
    const contentType = req.get("Content-Type");
    const createTargetIfMissing = req.get("Create-Target-If-Missing") == "true";
    const applyIfContentPreexists =
      req.get("Apply-If-Content-Preexists") == "true";
    const trimTargetWhitespace = req.get("Trim-Target-Whitespace") == "true";
    const targetDelimiter = req.get("Target-Delimiter") || "::";

    const target =
      targetType == "heading" ? rawTarget.split(targetDelimiter) : rawTarget;

    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) {
      this.returnCannedResponse(res, {
        statusCode: 404,
      });
      return;
    }
    const fileContents = await this.app.vault.read(file);

    if (!targetType) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.MissingTargetTypeHeader,
      });
      return;
    }
    if (!["heading", "block", "frontmatter"].includes(targetType)) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidTargetTypeHeader,
      });
      return;
    }
    if (!operation) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.MissingOperation,
      });
      return;
    }
    if (!["append", "prepend", "replace"].includes(operation)) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidOperation,
      });
      return;
    }
    if (!path || path.endsWith("/")) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.RequestMethodValidOnlyForFiles,
      });
      return;
    }

    const instruction: PatchInstruction = {
      operation: operation as PatchOperation,
      targetType: targetType as PatchTargetType,
      target,
      contentType: contentType as ContentType,
      content: req.body,
      applyIfContentPreexists,
      trimTargetWhitespace,
      createTargetIfMissing,
    } as PatchInstruction;

    try {
      const patched = applyPatch(fileContents, instruction);
      await this.app.vault.adapter.write(path, patched);
      res.status(200).send(patched);
    } catch (e) {
      if (e instanceof PatchFailed) {
        this.returnCannedResponse(res, {
          errorCode: ErrorCode.PatchFailed,
          message: e.reason,
        });
      } else {
        this.returnCannedResponse(res, {
          statusCode: 500,
          message: e.message,
        });
      }
    }
  }

  async _vaultPatch(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    if (!path || path.endsWith("/")) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.RequestMethodValidOnlyForFiles,
      });
      return;
    }

    // Route canvas files to canvas-specific handler
    const contentType = req.get("Content-Type");
    if (isCanvasFile(path) && contentType === ContentTypes.canvasPatchJson) {
      return this._canvasPatch(path, req, res);
    }

    if (req.get("Heading") && !req.get("Target-Type")) {
      return this._vaultPatchV2(path, req, res);
    }
    return this._vaultPatchV3(path, req, res);
  }

  async _canvasPatch(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const targetType = req.get("Target-Type") as CanvasPatchTargetType;
    const operation = req.get("Operation") as CanvasPatchOperation;
    const target = req.get("Target")
      ? decodeURIComponent(req.get("Target"))
      : undefined;

    // Validate headers
    if (!targetType) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.MissingTargetTypeHeader,
      });
      return;
    }

    if (!["node", "edge", "nodes", "edges"].includes(targetType)) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidCanvasPatchTargetType,
      });
      return;
    }

    // For single operations, operation header is required
    if ((targetType === "node" || targetType === "edge") && !operation) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.MissingOperation,
      });
      return;
    }

    if (operation && !["add", "update", "delete"].includes(operation)) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidCanvasPatchOperation,
      });
      return;
    }

    // Read existing canvas
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) {
      this.returnCannedResponse(res, { statusCode: 404 });
      return;
    }

    let canvas: CanvasData;
    try {
      const content = await this.app.vault.read(file);
      canvas = parseCanvasData(content);
    } catch (e) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidCanvasFormat,
        message: e.message,
      });
      return;
    }

    try {
      // Handle batch operations
      if (targetType === "nodes") {
        canvas = this.applyCanvasNodesBatch(
          canvas,
          req.body as CanvasBatchPatch<CanvasNode>
        );
      } else if (targetType === "edges") {
        canvas = this.applyCanvasEdgesBatch(
          canvas,
          req.body as CanvasBatchPatch<CanvasEdge>
        );
      }
      // Handle single operations
      else if (targetType === "node") {
        canvas = this.applyCanvasNodeOperation(
          canvas,
          operation,
          target,
          req.body
        );
      } else if (targetType === "edge") {
        canvas = this.applyCanvasEdgeOperation(
          canvas,
          operation,
          target,
          req.body
        );
      }

      // Validate the result
      validateCanvasStructure(canvas);

      // Write back
      const newContent = JSON.stringify(canvas, null, 2);
      await this.app.vault.adapter.write(path, newContent);

      res.status(200).json(canvas);
    } catch (e) {
      if (e.errorCode) {
        this.returnCannedResponse(res, {
          errorCode: e.errorCode,
          message: e.message,
        });
      } else {
        this.returnCannedResponse(res, {
          errorCode: ErrorCode.PatchFailed,
          message: e.message,
        });
      }
    }
  }

  applyCanvasNodesBatch(
    canvas: CanvasData,
    batch: CanvasBatchPatch<CanvasNode>
  ): CanvasData {
    const result = {
      ...canvas,
      nodes: [...canvas.nodes],
      edges: [...canvas.edges],
    };

    // Process deletions first
    if (batch.delete) {
      const deleteSet = new Set(batch.delete);
      result.nodes = result.nodes.filter((n) => !deleteSet.has(n.id));
      // Also remove edges that reference deleted nodes
      result.edges = result.edges.filter(
        (e) => !deleteSet.has(e.fromNode) && !deleteSet.has(e.toNode)
      );
    }

    // Process updates
    if (batch.update) {
      for (const [id, updates] of Object.entries(batch.update)) {
        const idx = result.nodes.findIndex((n) => n.id === id);
        if (idx === -1) {
          const error = new Error(`Node ${id} not found`);
          (error as any).errorCode = ErrorCode.CanvasNodeNotFound;
          throw error;
        }
        result.nodes[idx] = { ...result.nodes[idx], ...updates } as CanvasNode;
      }
    }

    // Process additions
    if (batch.add) {
      const existingIds = new Set(result.nodes.map((n) => n.id));
      for (const node of batch.add) {
        if (existingIds.has(node.id)) {
          const error = new Error(`Node ${node.id} already exists`);
          (error as any).errorCode = ErrorCode.CanvasNodeIdConflict;
          throw error;
        }
        validateCanvasNode(node);
        result.nodes.push(node);
      }
    }

    return result;
  }

  applyCanvasEdgesBatch(
    canvas: CanvasData,
    batch: CanvasBatchPatch<CanvasEdge>
  ): CanvasData {
    const result = {
      ...canvas,
      nodes: [...canvas.nodes],
      edges: [...canvas.edges],
    };
    const nodeIds = new Set(result.nodes.map((n) => n.id));

    // Process deletions first
    if (batch.delete) {
      const deleteSet = new Set(batch.delete);
      result.edges = result.edges.filter((e) => !deleteSet.has(e.id));
    }

    // Process updates
    if (batch.update) {
      for (const [id, updates] of Object.entries(batch.update)) {
        const idx = result.edges.findIndex((e) => e.id === id);
        if (idx === -1) {
          const error = new Error(`Edge ${id} not found`);
          (error as any).errorCode = ErrorCode.CanvasEdgeNotFound;
          throw error;
        }
        const updated = { ...result.edges[idx], ...updates } as CanvasEdge;
        // Validate node references
        if (!nodeIds.has(updated.fromNode) || !nodeIds.has(updated.toNode)) {
          const error = new Error(`Edge references non-existent node`);
          (error as any).errorCode = ErrorCode.CanvasEdgeReferencesInvalidNode;
          throw error;
        }
        result.edges[idx] = updated;
      }
    }

    // Process additions
    if (batch.add) {
      const existingIds = new Set(result.edges.map((e) => e.id));
      for (const edge of batch.add) {
        if (existingIds.has(edge.id)) {
          const error = new Error(`Edge ${edge.id} already exists`);
          (error as any).errorCode = ErrorCode.CanvasEdgeIdConflict;
          throw error;
        }
        if (!nodeIds.has(edge.fromNode) || !nodeIds.has(edge.toNode)) {
          const error = new Error(`Edge references non-existent node`);
          (error as any).errorCode = ErrorCode.CanvasEdgeReferencesInvalidNode;
          throw error;
        }
        validateCanvasEdge(edge);
        result.edges.push(edge);
      }
    }

    return result;
  }

  applyCanvasNodeOperation(
    canvas: CanvasData,
    operation: CanvasPatchOperation,
    target: string | undefined,
    body: unknown
  ): CanvasData {
    const result = {
      ...canvas,
      nodes: [...canvas.nodes],
      edges: [...canvas.edges],
    };

    switch (operation) {
      case "add": {
        const newNode = body as CanvasNode;
        validateCanvasNode(newNode);
        if (result.nodes.some((n) => n.id === newNode.id)) {
          const error = new Error(`Node ${newNode.id} already exists`);
          (error as any).errorCode = ErrorCode.CanvasNodeIdConflict;
          throw error;
        }
        result.nodes.push(newNode);
        break;
      }

      case "update": {
        if (!target) {
          const error = new Error("Target node ID required");
          (error as any).errorCode = ErrorCode.CanvasNodeIdRequired;
          throw error;
        }
        const updateIdx = result.nodes.findIndex((n) => n.id === target);
        if (updateIdx === -1) {
          const error = new Error(`Node ${target} not found`);
          (error as any).errorCode = ErrorCode.CanvasNodeNotFound;
          throw error;
        }
        result.nodes[updateIdx] = {
          ...result.nodes[updateIdx],
          ...(body as Partial<CanvasNode>),
        } as CanvasNode;
        break;
      }

      case "delete": {
        if (!target) {
          const error = new Error("Target node ID required");
          (error as any).errorCode = ErrorCode.CanvasNodeIdRequired;
          throw error;
        }
        const deleteIdx = result.nodes.findIndex((n) => n.id === target);
        if (deleteIdx === -1) {
          const error = new Error(`Node ${target} not found`);
          (error as any).errorCode = ErrorCode.CanvasNodeNotFound;
          throw error;
        }
        result.nodes.splice(deleteIdx, 1);
        // Remove edges referencing this node
        result.edges = result.edges.filter(
          (e) => e.fromNode !== target && e.toNode !== target
        );
        break;
      }
    }

    return result;
  }

  applyCanvasEdgeOperation(
    canvas: CanvasData,
    operation: CanvasPatchOperation,
    target: string | undefined,
    body: unknown
  ): CanvasData {
    const result = {
      ...canvas,
      nodes: [...canvas.nodes],
      edges: [...canvas.edges],
    };
    const nodeIds = new Set(result.nodes.map((n) => n.id));

    switch (operation) {
      case "add": {
        const newEdge = body as CanvasEdge;
        validateCanvasEdge(newEdge);
        if (result.edges.some((e) => e.id === newEdge.id)) {
          const error = new Error(`Edge ${newEdge.id} already exists`);
          (error as any).errorCode = ErrorCode.CanvasEdgeIdConflict;
          throw error;
        }
        if (!nodeIds.has(newEdge.fromNode) || !nodeIds.has(newEdge.toNode)) {
          const error = new Error(`Edge references non-existent node`);
          (error as any).errorCode = ErrorCode.CanvasEdgeReferencesInvalidNode;
          throw error;
        }
        result.edges.push(newEdge);
        break;
      }

      case "update": {
        if (!target) {
          const error = new Error("Target edge ID required");
          (error as any).errorCode = ErrorCode.CanvasEdgeIdRequired;
          throw error;
        }
        const updateIdx = result.edges.findIndex((e) => e.id === target);
        if (updateIdx === -1) {
          const error = new Error(`Edge ${target} not found`);
          (error as any).errorCode = ErrorCode.CanvasEdgeNotFound;
          throw error;
        }
        const updated = { ...result.edges[updateIdx], ...(body as Partial<CanvasEdge>) } as CanvasEdge;
        if (!nodeIds.has(updated.fromNode) || !nodeIds.has(updated.toNode)) {
          const error = new Error(`Edge references non-existent node`);
          (error as any).errorCode = ErrorCode.CanvasEdgeReferencesInvalidNode;
          throw error;
        }
        result.edges[updateIdx] = updated;
        break;
      }

      case "delete": {
        if (!target) {
          const error = new Error("Target edge ID required");
          (error as any).errorCode = ErrorCode.CanvasEdgeIdRequired;
          throw error;
        }
        const deleteIdx = result.edges.findIndex((e) => e.id === target);
        if (deleteIdx === -1) {
          const error = new Error(`Edge ${target} not found`);
          (error as any).errorCode = ErrorCode.CanvasEdgeNotFound;
          throw error;
        }
        result.edges.splice(deleteIdx, 1);
        break;
      }
    }

    return result;
  }

  async vaultPatch(req: express.Request, res: express.Response): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    return this._vaultPatch(path, req, res);
  }

  async _vaultPost(
    filepath: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    if (!filepath || filepath.endsWith("/")) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.RequestMethodValidOnlyForFiles,
      });
      return;
    }

    if (typeof req.body != "string") {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.TextContentEncodingRequired,
      });
      return;
    }

    try {
      await this.app.vault.createFolder(path.dirname(filepath));
    } catch {
      // the folder/file already exists, but we don't care
    }

    let fileContents = "";
    const file = this.app.vault.getAbstractFileByPath(filepath);
    if (file instanceof TFile) {
      fileContents = await this.app.vault.read(file);
      if (!fileContents.endsWith("\n")) {
        fileContents += "\n";
      }
    }

    fileContents += req.body;

    await this.app.vault.adapter.write(filepath, fileContents);

    this.returnCannedResponse(res, { statusCode: 204 });
    return;
  }

  async vaultPost(req: express.Request, res: express.Response): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    return this._vaultPost(path, req, res);
  }

  async _vaultDelete(
    path: string,
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    if (!path || path.endsWith("/")) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.RequestMethodValidOnlyForFiles,
      });
      return;
    }

    const pathExists = await this.app.vault.adapter.exists(path);
    if (!pathExists) {
      this.returnCannedResponse(res, { statusCode: 404 });
      return;
    }

    await this.app.vault.adapter.remove(path);
    this.returnCannedResponse(res, { statusCode: 204 });
    return;
  }

  async vaultDelete(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    return this._vaultDelete(path, req, res);
  }

  getPeriodicNoteInterface(): Record<string, PeriodicNoteInterface> {
    return {
      daily: {
        settings: periodicNotes.getDailyNoteSettings(),
        loaded: periodicNotes.appHasDailyNotesPluginLoaded(),
        create: periodicNotes.createDailyNote,
        get: periodicNotes.getDailyNote,
        getAll: periodicNotes.getAllDailyNotes,
      },
      weekly: {
        settings: periodicNotes.getWeeklyNoteSettings(),
        loaded: periodicNotes.appHasWeeklyNotesPluginLoaded(),
        create: periodicNotes.createWeeklyNote,
        get: periodicNotes.getWeeklyNote,
        getAll: periodicNotes.getAllWeeklyNotes,
      },
      monthly: {
        settings: periodicNotes.getMonthlyNoteSettings(),
        loaded: periodicNotes.appHasMonthlyNotesPluginLoaded(),
        create: periodicNotes.createMonthlyNote,
        get: periodicNotes.getMonthlyNote,
        getAll: periodicNotes.getAllMonthlyNotes,
      },
      quarterly: {
        settings: periodicNotes.getQuarterlyNoteSettings(),
        loaded: periodicNotes.appHasQuarterlyNotesPluginLoaded(),
        create: periodicNotes.createQuarterlyNote,
        get: periodicNotes.getQuarterlyNote,
        getAll: periodicNotes.getAllQuarterlyNotes,
      },
      yearly: {
        settings: periodicNotes.getYearlyNoteSettings(),
        loaded: periodicNotes.appHasYearlyNotesPluginLoaded(),
        create: periodicNotes.createYearlyNote,
        get: periodicNotes.getYearlyNote,
        getAll: periodicNotes.getAllYearlyNotes,
      },
    };
  }

  periodicGetInterface(
    period: string
  ): [PeriodicNoteInterface | null, ErrorCode | null] {
    const periodic = this.getPeriodicNoteInterface();
    if (!periodic[period]) {
      return [null, ErrorCode.PeriodDoesNotExist];
    }
    if (!periodic[period].loaded) {
      return [null, ErrorCode.PeriodIsNotEnabled];
    }

    return [periodic[period], null];
  }

  periodicGetNote(
    periodName: string,
    timestamp: number
  ): [TFile | null, ErrorCode | null] {
    const [period, err] = this.periodicGetInterface(periodName);
    if (err) {
      return [null, err];
    }

    const now = (window as any).moment(timestamp);
    const all = period.getAll();

    const file = period.get(now, all);
    if (!file) {
      return [null, ErrorCode.PeriodicNoteDoesNotExist];
    }

    return [file, null];
  }

  async periodicGetOrCreateNote(
    periodName: string,
    timestamp: number
  ): Promise<[TFile | null, ErrorCode | null]> {
    const [gottenFile, err] = this.periodicGetNote(periodName, timestamp);
    let file = gottenFile;
    if (err === ErrorCode.PeriodicNoteDoesNotExist) {
      const [period] = this.periodicGetInterface(periodName);
      const now = (window as any).moment(Date.now());

      file = await period.create(now);

      const metadataCachePromise = new Promise<CachedMetadata>((resolve) => {
        let cache: CachedMetadata = null;

        const interval: ReturnType<typeof setInterval> = setInterval(() => {
          cache = this.app.metadataCache.getFileCache(file);
          if (cache) {
            clearInterval(interval);
            resolve(cache);
          }
        }, 100);
      });
      await metadataCachePromise;
    } else if (err) {
      return [null, err];
    }

    return [file, null];
  }

  redirectToVaultPath(
    file: TFile,
    req: express.Request,
    res: express.Response,
    handler: (path: string, req: express.Request, res: express.Response) => void
  ): void {
    const path = file.path;
    res.set("Content-Location", encodeURI(path));

    return handler(path, req, res);
  }

  getPeriodicDateFromParams(params: any): number {
    const { year, month, day } = params;

    if (year && month && day) {
      const date = new Date(year, month - 1, day);
      return date.getTime();
    }

    return Date.now();
  }

  async periodicGet(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const date = this.getPeriodicDateFromParams(req.params);
    const [file, err] = this.periodicGetNote(req.params.period, date);
    if (err) {
      this.returnCannedResponse(res, { errorCode: err });
      return;
    }

    return this.redirectToVaultPath(file, req, res, this._vaultGet.bind(this));
  }

  async periodicPut(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const date = this.getPeriodicDateFromParams(req.params);
    const [file, err] = await this.periodicGetOrCreateNote(
      req.params.period,
      date
    );
    if (err) {
      this.returnCannedResponse(res, { errorCode: err });
      return;
    }

    return this.redirectToVaultPath(file, req, res, this._vaultPut.bind(this));
  }

  async periodicPost(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const date = this.getPeriodicDateFromParams(req.params);
    const [file, err] = await this.periodicGetOrCreateNote(
      req.params.period,
      date
    );
    if (err) {
      this.returnCannedResponse(res, { errorCode: err });
      return;
    }

    return this.redirectToVaultPath(file, req, res, this._vaultPost.bind(this));
  }

  async periodicPatch(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const date = this.getPeriodicDateFromParams(req.params);
    const [file, err] = await this.periodicGetOrCreateNote(
      req.params.period,
      date
    );
    if (err) {
      this.returnCannedResponse(res, { errorCode: err });
      return;
    }

    return this.redirectToVaultPath(
      file,
      req,
      res,
      this._vaultPatch.bind(this)
    );
  }

  async periodicDelete(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const date = this.getPeriodicDateFromParams(req.params);
    const [file, err] = this.periodicGetNote(req.params.period, date);
    if (err) {
      this.returnCannedResponse(res, { errorCode: err });
      return;
    }

    return this.redirectToVaultPath(
      file,
      req,
      res,
      this._vaultDelete.bind(this)
    );
  }

  async activeFileGet(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const file = this.app.workspace.getActiveFile();

    return this.redirectToVaultPath(file, req, res, this._vaultGet.bind(this));
  }

  async activeFilePut(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const file = this.app.workspace.getActiveFile();

    return this.redirectToVaultPath(file, req, res, this._vaultPut.bind(this));
  }

  async activeFilePost(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const file = this.app.workspace.getActiveFile();

    return this.redirectToVaultPath(file, req, res, this._vaultPost.bind(this));
  }

  async activeFilePatch(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const file = this.app.workspace.getActiveFile();

    return this.redirectToVaultPath(
      file,
      req,
      res,
      this._vaultPatch.bind(this)
    );
  }

  async activeFileDelete(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const file = this.app.workspace.getActiveFile();

    return this.redirectToVaultPath(
      file,
      req,
      res,
      this._vaultDelete.bind(this)
    );
  }

  async commandGet(req: express.Request, res: express.Response): Promise<void> {
    const commands: Command[] = [];
    for (const commandName in this.app.commands.commands) {
      commands.push({
        id: commandName,
        name: this.app.commands.commands[commandName].name,
      });
    }

    const commandResponse = {
      commands: commands,
    };

    res.json(commandResponse);
  }

  async commandPost(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const cmd = this.app.commands.commands[req.params.commandId];

    if (!cmd) {
      this.returnCannedResponse(res, { statusCode: 404 });
      return;
    }

    try {
      this.app.commands.executeCommandById(req.params.commandId);
    } catch (e) {
      this.returnCannedResponse(res, { statusCode: 500, message: e.message });
      return;
    }

    this.returnCannedResponse(res, { statusCode: 204 });
    return;
  }

  async searchSimplePost(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const results: (SearchResponseItem | CanvasSearchResponseItem)[] = [];

    const query: string = req.query.query as string;
    if (!(typeof query === "string")) {
      return this.returnCannedResponse(res, {
        message: "A single '?query=' parameter is required.",
        errorCode: ErrorCode.InvalidSearch,
      });
    }
    const contextLength: number =
      parseInt(req.query.contextLength as string, 10) ?? 100;
    let search: ReturnType<typeof prepareSimpleSearch>;
    try {
      search = prepareSimpleSearch(query);
    } catch (e) {
      console.error("Could not prepare simple search: ", e);
      return this.returnCannedResponse(res, {
        message: `${e}`,
        errorCode: ErrorCode.ErrorPreparingSimpleSearch,
      });
    }

    // Search markdown files
    for (const file of this.app.vault.getMarkdownFiles()) {
      const cachedContents = await this.app.vault.cachedRead(file);
      const result = search(cachedContents);
      if (result) {
        const contextMatches: SearchContext[] = [];
        for (const match of result.matches) {
          contextMatches.push({
            match: {
              start: match[0],
              end: match[1],
            },
            context: cachedContents.slice(
              Math.max(match[0] - contextLength, 0),
              match[1] + contextLength
            ),
          });
        }

        results.push({
          filename: file.path,
          score: result.score,
          matches: contextMatches,
        });
      }
    }

    // Search canvas files
    for (const file of this.app.vault.getFiles()) {
      if (!isCanvasFile(file.path)) {
        continue;
      }

      try {
        const content = await this.app.vault.cachedRead(file);
        const canvasData = parseCanvasData(content);
        const contextMatches: CanvasSearchContext[] = [];
        let bestScore = 0;

        // Search through text nodes
        for (const node of canvasData.nodes) {
          if (node.type === "text") {
            const result = search(node.text);
            if (result) {
              if (result.score > bestScore) {
                bestScore = result.score;
              }
              for (const match of result.matches) {
                contextMatches.push({
                  match: {
                    start: match[0],
                    end: match[1],
                  },
                  context: node.text.slice(
                    Math.max(match[0] - contextLength, 0),
                    match[1] + contextLength
                  ),
                  nodeId: node.id,
                  nodeType: "text",
                });
              }
            }
          }
        }

        if (contextMatches.length > 0) {
          results.push({
            filename: file.path,
            score: bestScore,
            matches: contextMatches,
            isCanvas: true,
          });
        }
      } catch (e) {
        // Skip invalid canvas files
        console.error(`Error searching canvas file ${file.path}: ${e}`);
      }
    }

    results.sort((a, b) => (a.score > b.score ? 1 : -1));
    res.json(results);
  }

  valueIsSaneTruthy(value: unknown): boolean {
    if (value === undefined || value === null) {
      return false;
    } else if (Array.isArray(value)) {
      return value.length > 0;
    } else if (typeof value === "object") {
      return Object.keys(value).length > 0;
    }
    return Boolean(value);
  }

  async searchQueryPost(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    const dataviewApi = getDataviewAPI();

    const handlers: Record<string, () => Promise<SearchJsonResponseItem[]>> = {
      [ContentTypes.dataviewDql]: async () => {
        const results: SearchJsonResponseItem[] = [];
        const dataviewResults = await dataviewApi.tryQuery(req.body);

        const fileColumn =
          dataviewApi.evaluationContext.settings.tableIdColumnName;

        if (dataviewResults.type !== "table") {
          throw new Error("Only TABLE dataview queries are supported.");
        }
        if (!dataviewResults.headers.includes(fileColumn)) {
          throw new Error("TABLE WITHOUT ID queries are not supported.");
        }

        for (const dataviewResult of dataviewResults.values) {
          const fieldValues: Record<string, any> = {};

          dataviewResults.headers.forEach((value: string, index: number) => {
            if (value !== fileColumn) {
              fieldValues[value] = dataviewResult[index];
            }
          });

          results.push({
            filename: dataviewResult[0].path,
            result: fieldValues,
          });
        }

        return results;
      },
      [ContentTypes.jsonLogic]: async () => {
        const results: SearchJsonResponseItem[] = [];

        for (const file of this.app.vault.getMarkdownFiles()) {
          const fileContext = await this.getFileMetadataObject(file);

          try {
            const fileResult = jsonLogic.apply(req.body, fileContext);

            if (this.valueIsSaneTruthy(fileResult)) {
              results.push({
                filename: file.path,
                result: fileResult,
              });
            }
          } catch (e) {
            throw new Error(`${e.message} (while processing ${file.path})`);
          }
        }

        return results;
      },
    };
    const contentType = req.headers["content-type"];

    if (!contentType) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.ContentTypeSpecificationRequired,
      });
      return;
    } else if (!handlers[contentType]) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidContentType,
      });
      return;
    }

    try {
      const results = await handlers[contentType]();
      res.json(results);
    } catch (e) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidFilterQuery,
        message: `${e.message}`,
      });
      return;
    }
  }

  async openPost(req: express.Request, res: express.Response): Promise<void> {
    const path = decodeURIComponent(
      req.path.slice(req.path.indexOf("/", 1) + 1)
    );

    const query = queryString.parseUrl(req.originalUrl, {
      parseBooleans: true,
    }).query;
    const newLeaf = Boolean(query.newLeaf);

    this.app.workspace.openLinkText(path, "/", newLeaf);

    res.json();
  }

  async certificateGet(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    res.set(
      "Content-type",
      `application/octet-stream; filename="${CERT_NAME}"`
    );
    res.status(200).send(this.settings.crypto.cert);
  }

  async openapiYamlGet(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    res.setHeader("Content-Type", "application/yaml; charset=utf-8");
    res.status(200).send(openapiYaml);
  }

  async notFoundHandler(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void> {
    this.returnCannedResponse(res, {
      statusCode: 404,
    });
    return;
  }

  async errorHandler(
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void> {
    if (err.stack) {
      console.error(err.stack);
    } else {
      console.error("No stack available!");
    }
    if (err instanceof SyntaxError) {
      this.returnCannedResponse(res, {
        errorCode: ErrorCode.InvalidContentForContentType,
      });
      return;
    }
    this.returnCannedResponse(res, {
      statusCode: 500,
      message: err.message,
    });
    return;
  }

  setupRouter() {
    this.api.use((req, res, next) => {
      const originalSend = res.send;
      res.send = function (body, ...args) {
        console.log(`[REST API] ${req.method} ${req.url} => ${res.statusCode}`);

        return originalSend.apply(res, [body, ...args]);
      };
      next();
    });
    this.api.use(responseTime());
    this.api.use(cors());
    this.api.use(this.authenticationMiddleware.bind(this));
    this.api.use(
      bodyParser.text({
        type: ContentTypes.dataviewDql,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.json({
        type: ContentTypes.json,
        strict: false,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.json({
        type: ContentTypes.olrapiNoteJson,
        strict: false,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.json({
        type: ContentTypes.jsonLogic,
        strict: false,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.json({
        type: ContentTypes.canvasJson,
        strict: false,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.json({
        type: ContentTypes.canvasPatchJson,
        strict: false,
        limit: MaximumRequestSize,
      })
    );
    this.api.use(
      bodyParser.text({ type: "text/*", limit: MaximumRequestSize })
    );
    this.api.use(bodyParser.raw({ type: "*/*", limit: MaximumRequestSize }));

    this.api
      .route("/active/")
      .get(this.activeFileGet.bind(this))
      .put(this.activeFilePut.bind(this))
      .patch(this.activeFilePatch.bind(this))
      .post(this.activeFilePost.bind(this))
      .delete(this.activeFileDelete.bind(this));

    this.api
      .route("/vault/*")
      .get(this.vaultGet.bind(this))
      .put(this.vaultPut.bind(this))
      .patch(this.vaultPatch.bind(this))
      .post(this.vaultPost.bind(this))
      .delete(this.vaultDelete.bind(this));

    this.api
      .route("/periodic/:period/")
      .get(this.periodicGet.bind(this))
      .put(this.periodicPut.bind(this))
      .patch(this.periodicPatch.bind(this))
      .post(this.periodicPost.bind(this))
      .delete(this.periodicDelete.bind(this));
    this.api
      .route("/periodic/:period/:year/:month/:day/")
      .get(this.periodicGet.bind(this))
      .put(this.periodicPut.bind(this))
      .patch(this.periodicPatch.bind(this))
      .post(this.periodicPost.bind(this))
      .delete(this.periodicDelete.bind(this));

    this.api.route("/commands/").get(this.commandGet.bind(this));
    this.api.route("/commands/:commandId/").post(this.commandPost.bind(this));

    this.api.route("/search/").post(this.searchQueryPost.bind(this));
    this.api.route("/search/simple/").post(this.searchSimplePost.bind(this));

    this.api.route("/open/*").post(this.openPost.bind(this));

    this.api.get(`/${CERT_NAME}`, this.certificateGet.bind(this));
    this.api.get("/openapi.yaml", this.openapiYamlGet.bind(this));
    this.api.get("/", this.root.bind(this));

    this.api.use(this.apiExtensionRouter);

    this.api.use(this.notFoundHandler.bind(this));
    this.api.use(this.errorHandler.bind(this));
  }
}
