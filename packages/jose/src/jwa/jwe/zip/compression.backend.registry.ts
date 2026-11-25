import type { CompressionBackend } from "./compression.backend.ts";
import { DEFCompressionBackend } from "./def/def.compression.backend.ts";

/**
 * Supported Compression Backends.
 */
export const COMPRESSION_BACKEND_REGISTRY: CompressionBackend[] = [new DEFCompressionBackend()];
