import { FileStats } from "obsidian";
import {
  CanvasData,
  CanvasNode,
  CanvasEdge,
  CanvasMetadataObject,
  CanvasTextNode,
  CanvasFileNode,
} from "./types";

export function isCanvasFile(path: string): boolean {
  return path.toLowerCase().endsWith(".canvas");
}

export function parseCanvasData(content: string): CanvasData {
  const data = JSON.parse(content);
  validateCanvasStructure(data);
  return data;
}

export function validateCanvasStructure(
  data: unknown
): asserts data is CanvasData {
  if (!data || typeof data !== "object") {
    throw new Error("Canvas data must be an object");
  }

  const canvas = data as Record<string, unknown>;

  // nodes and edges are optional per JSON Canvas spec, default to empty arrays
  if (canvas.nodes !== undefined && !Array.isArray(canvas.nodes)) {
    throw new Error("Canvas nodes must be an array");
  }

  if (canvas.edges !== undefined && !Array.isArray(canvas.edges)) {
    throw new Error("Canvas edges must be an array");
  }

  // Normalize: ensure nodes and edges exist
  if (!canvas.nodes) {
    (canvas as unknown as CanvasData).nodes = [];
  }
  if (!canvas.edges) {
    (canvas as unknown as CanvasData).edges = [];
  }

  // Validate each node
  for (const node of (canvas as unknown as CanvasData).nodes) {
    validateCanvasNode(node);
  }

  // Validate each edge
  for (const edge of (canvas as unknown as CanvasData).edges) {
    validateCanvasEdge(edge);
  }
}

export function validateCanvasNode(node: unknown): asserts node is CanvasNode {
  if (!node || typeof node !== "object") {
    throw new Error("Node must be an object");
  }

  const n = node as Record<string, unknown>;

  if (typeof n.id !== "string" || !n.id) {
    throw new Error("Node must have a string id");
  }

  if (!["text", "file", "link", "group"].includes(n.type as string)) {
    throw new Error(`Invalid node type: ${n.type}`);
  }

  if (typeof n.x !== "number" || typeof n.y !== "number") {
    throw new Error("Node must have numeric x and y coordinates");
  }

  if (typeof n.width !== "number" || typeof n.height !== "number") {
    throw new Error("Node must have numeric width and height");
  }

  // Type-specific validation
  switch (n.type) {
    case "text":
      if (typeof n.text !== "string") {
        throw new Error("Text node must have a text property");
      }
      break;
    case "file":
      if (typeof n.file !== "string") {
        throw new Error("File node must have a file property");
      }
      break;
    case "link":
      if (typeof n.url !== "string") {
        throw new Error("Link node must have a url property");
      }
      break;
    case "group":
      // Group nodes have optional properties only
      break;
  }
}

export function validateCanvasEdge(edge: unknown): asserts edge is CanvasEdge {
  if (!edge || typeof edge !== "object") {
    throw new Error("Edge must be an object");
  }

  const e = edge as Record<string, unknown>;

  if (typeof e.id !== "string" || !e.id) {
    throw new Error("Edge must have a string id");
  }

  if (typeof e.fromNode !== "string" || !e.fromNode) {
    throw new Error("Edge must have a fromNode property");
  }

  if (typeof e.toNode !== "string" || !e.toNode) {
    throw new Error("Edge must have a toNode property");
  }

  const validSides = ["top", "right", "bottom", "left"];
  if (e.fromSide && !validSides.includes(e.fromSide as string)) {
    throw new Error(`Invalid fromSide: ${e.fromSide}`);
  }

  if (e.toSide && !validSides.includes(e.toSide as string)) {
    throw new Error(`Invalid toSide: ${e.toSide}`);
  }

  const validEnds = ["none", "arrow"];
  if (e.fromEnd && !validEnds.includes(e.fromEnd as string)) {
    throw new Error(`Invalid fromEnd: ${e.fromEnd}`);
  }

  if (e.toEnd && !validEnds.includes(e.toEnd as string)) {
    throw new Error(`Invalid toEnd: ${e.toEnd}`);
  }
}

export function getCanvasMetadata(
  canvas: CanvasData,
  path: string,
  stat: FileStats
): CanvasMetadataObject {
  const nodeTypes = { text: 0, file: 0, link: 0, group: 0 };
  const referencedFiles: string[] = [];

  for (const node of canvas.nodes) {
    nodeTypes[node.type]++;
    if (node.type === "file") {
      referencedFiles.push((node as CanvasFileNode).file);
    }
  }

  return {
    canvas,
    metadata: {
      nodeCount: canvas.nodes.length,
      edgeCount: canvas.edges.length,
      nodeTypes,
      referencedFiles: [...new Set(referencedFiles)],
    },
    stat,
    path,
  };
}

export function getTextFromCanvasNodes(canvas: CanvasData): string[] {
  const texts: string[] = [];
  for (const node of canvas.nodes) {
    if (node.type === "text") {
      texts.push((node as CanvasTextNode).text);
    }
  }
  return texts;
}
