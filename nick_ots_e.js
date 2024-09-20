/// <reference types="@webgpu/types" />
"use strict";

// TODO: Consider mixing in some extra data regarding the parameter set (PRF, maybe more?).
// TODO: WebGPU implementation
// TODO: Checksum chain values are in little endian. Fix?
// TODO: Move form inputs to dedicated classes?

// Public key generation form
const FORM_GENERATE_PUBLIC_KEY_NAME = "ots-generate-public-key";
const FORM_GENERATE_PUBLIC_KEY_ELEMENT_MASTER_KEY_NAME = "master-key";
const FORM_GENERATE_PUBLIC_KEY_ELEMENT_SUBMIT_NAME = "submit";

// Signature generation form
const FORM_GENERATE_SIGNATURE_NAME = "ots-generate-signature";
const FORM_GENERATE_SIGNATURE_ELEMENT_MASTER_KEY_NAME = "master-key";
const FORM_GENERATE_SIGNATURE_ELEMENT_CONTENT_HASH_NAME = "content-hash";
const FORM_GENERATE_SIGNATURE_ELEMENT_SUBMIT_NAME = "submit";

// Signature verification form
const FORM_VERIFY_NAME = "ots-verify";
const FORM_VERIFY_ELEMENT_PUBLIC_KEY_NAME = "public-key";
const FORM_VERIFY_ELEMENT_SIGNATURE_NAME = "signature";
const FORM_VERIFY_ELEMENT_CONTENT_HASH_NAME = "content-hash";
const FORM_VERIFY_ELEMENT_SUBMIT_NAME = "submit";

// Public key output
const GENERATE_PUBLIC_KEY_OUTPUT_CONTAINER_ID = "generate-public-key-output-container";
const GENERATE_PUBLIC_KEY_OUTPUT_PUBLIC_KEY_ID = "generate-public-key-output-public-key";

// Signature generation output
const GENERATE_SIGNATURE_OUTPUT_CONTAINER_ID = "generate-signature-output-container";
const GENERATE_SIGNATURE_OUTPUT_SIGNATURE_TEXTAREA_ID = "generate-signature-output-signature-textarea";
const GENERATE_SIGNATURE_OUTPUT_SIGNATURE_ANCHOR_ID = "generate-signature-output-signature-anchor";

// Signature verification output
const VERIFY_OUTPUT_CONTAINER_ID = "verify-output-container";
const VERIFY_OUTPUT_STATUS_PASS_ID = "verify-output-status-pass";
const VERIFY_OUTPUT_STATUS_FAIL_ID = "verify-output-status-fail";

// Text replacement placeholders
const GENERATE_SIGNATURE_OUTPUT_SIGNATURE_ANCHOR_DOWNLOAD_PATTERN_CONTENT_HASH_REPLACE = "{H}";

// Hash function properties
/** @type {DigestAlgo} */
const HASH_SHA256_NAME = "SHA-256";
const HASH_SHA256_BIT_LENGTH = 256;
const HASH_SHA256_BLOCK_BIT_LENGTH = 512;

const MAX_ACCEPTABLE_NUMBER_OF_GPU_DEVICE_LOSSES = 3;

const COMPUTE_SHADER_MODULE_LABEL = "Hash chain shader";
const COMPUTE_SHADER_MODULE_CODE = `
struct ChainProcess {
    numRequests: u32,
    requests: array<ChainRequest>
}

struct ChainRequest {
    n: u32,
    message: array<u32, 8>
}

@group(0) @binding(0) var<storage, read> input:ChainProcess;
@group(0) @binding(1) var<storage, read_write> hashes:array<array<u32, 8>>;

const k = array<u32, 64>(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

const hashInit = array<u32, 8>(
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
);

@compute @workgroup_size(65)
fn main(@builtin(local_invocation_index) i: u32) {
    if(i >= input.numRequests) {
        return;
    }

    let req: ChainRequest = input.requests[i];
    sha256Chain(req.message, req.n, &(hashes[i]));
}

fn sha256Chain(
    message: array<u32, 8>,
    n: u32,
    hash: ptr<storage, array<u32, 8>, read_write>
) {
    var a = message;
    var b = array<u32, 8>();

    swapMessageEndianness(&a);

    // Chain
    for(var i: u32 = 0; i < n; i++) {
        sha256_oneBlock(&a, &b);
        a = b;
    }

    for(var i: u32 = 0; i < 8; i++) {
        (*hash)[i] = swapUint32Endianness(a[i]);
    }
}

fn sha256_oneBlock(
    message: ptr<function, array<u32, 8>>,
    hash: ptr<function, array<u32, 8>>
) {
    var messageSched = array<u32, 64>();

    var a: u32 = hashInit[0];
    var b: u32 = hashInit[1];
    var c: u32 = hashInit[2];
    var d: u32 = hashInit[3];
    var e: u32 = hashInit[4];
    var f: u32 = hashInit[5];
    var g: u32 = hashInit[6];
    var h: u32 = hashInit[7];

    for(var i: u32 = 0; i < 8; i++) {
        (*hash)[i] = hashInit[i];
    }

    for(var t: u32 = 0; t < 8; t++) {
        messageSched[t] = (*message)[t];
    }

    messageSched[8] = 0x80000000;
    messageSched[15] = 256;

    for(var t: u32 = 16; t < 64; t++) {
        messageSched[t] =
            sigmaLower1(messageSched[t-2]) +
            messageSched[t-7] +
            sigmaLower0(messageSched[t-15]) +
            messageSched[t-16];
    }

    for(var t = 0; t < 64; t++) {
        let temp1 =
            h +
            sigmaUpper1(e) +
            ch(e, f, g) +
            k[t] +
            messageSched[t];

        let temp2 =
            sigmaUpper0(a) +
            maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    (*hash)[0] += a;
    (*hash)[1] += b;
    (*hash)[2] += c;
    (*hash)[3] += d;
    (*hash)[4] += e;
    (*hash)[5] += f;
    (*hash)[6] += g;
    (*hash)[7] += h;
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32 - n));
}

fn sigmaUpper0(x: u32) -> u32 {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

fn sigmaUpper1(x: u32) -> u32 {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

fn sigmaLower0(x: u32) -> u32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

fn sigmaLower1(x: u32) -> u32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

fn swapUint32Endianness(num: u32) -> u32 {
    return (
        ((num >> 24) & 0x000000ff) |
        ((num >> 8)  & 0x0000ff00) |
        ((num << 8)  & 0x00ff0000) |
        ((num << 24) & 0xff000000)
    );
}

fn swapMessageEndianness(message: ptr<function, array<u32, 8>>) {
    for(var i: i32 = 0; i < 8; i++) {
        let word = (*message)[i];
        (*message)[i] =
            ((word >> 24) & 0x000000ff) |
            ((word >> 8)  & 0x0000ff00) |
            ((word << 8)  & 0x00ff0000) |
            ((word << 24) & 0xff000000);
    }
}`;

const COMPUTE_SHADER_PIPELINE_LABEL = "Hash chain pipeline";

const COMPUTE_SHADER_ENTRYPOINT_NAME = "main";

const COMPUTE_SHADER_DISPATCH_X = 1;
const COMPUTE_SHADER_DISPATCH_Y = 1;
const COMPUTE_SHADER_DISPATCH_Z = 1;

const COMPUTE_SHADER_WORKGROUP_SIZE = 65;

const COMPUTE_SHADER_HASH_BYTE_LENGTH = (HASH_SHA256_BIT_LENGTH / 8);

const COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_N_BYTE_LENGTH = 4;
const COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_BYTE_LENGTH =
    COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_N_BYTE_LENGTH +
    COMPUTE_SHADER_HASH_BYTE_LENGTH;

const COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_NUM_REQUESTS_BYTE_LENGTH = 4;
const COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_REQUESTS_BYTE_LENGTH =
    COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_BYTE_LENGTH * COMPUTE_SHADER_WORKGROUP_SIZE;
const COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_BYTE_LENGTH =
    COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_NUM_REQUESTS_BYTE_LENGTH +
    COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_REQUESTS_BYTE_LENGTH;

const COMPUTE_SHADER_GROUP0_LABEL = "Binding group 0";

const COMPUTE_SHADER_GROUP0_BUFFER_INPUT_LABEL = "Input buffer";
const COMPUTE_SHADER_GROUP0_BUFFER_INPUT_PROCESS_BINDING = 0;

const COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_LABEL = "Output buffer";
const COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BINDING = 1;

const COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BYTE_LENGTH =
    COMPUTE_SHADER_HASH_BYTE_LENGTH * COMPUTE_SHADER_WORKGROUP_SIZE;

const COMPUTE_SHADER_BUFFER_OUTPUT2_LABEL = "Mappable output buffer";
const COMPUTE_SHADER_BUFFER_OUTPUT2_HASHES_BYTE_LENGTH = COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BYTE_LENGTH;

// Misc.
const HEX_ALPHABET_LOWERCASE = "0123456789abcdef";

/** @type {GPUAdapter|null} */
let gpuAdapter = null;
/** @type {GPUDevice|null} */
let gpuDevice = null;

/** @type {GPUComputePipeline|null} */
let gpuComputePipeline = null;
/** @type {GPUBindGroup|null} */
let gpuComputeBindGroup0 = null;

/** @type {GPUBuffer|null} */
let gpuGroup0_buffer_input_gpuBuffer = null;
/** @type {ArrayBuffer|null} */
let gpuGroup0_buffer_input_arrayBuffer = null;
/** @type {DataView|null} */
let gpuGroup0_buffer_input_dataView = null;
let gpuGroup0_buffer_input_process_offset = -1;
let gpuGroup0_buffer_input_process_numRequests_offset = -1;
let gpuGroup0_buffer_input_process_requests_offset = -1;

/** @type {GPUBuffer|null} */
let gpuGroup0_buffer_output_gpuBuffer = null;
let gpuGroup0_buffer_output_hashes_offset = -1;

/** @type {GPUBuffer|null} */
let gpu_buffer_output2_gpuBuffer = null;
/** @type {Promise<void>|null} */
let gpu_buffer_output2_mapAsync_promise = null;
let gpu_buffer_output2_hashes_offset = -1;

let gpuNumDeviceLosses = 0;

/** @type {Number} */
let TEMP_digestOpCount = 0; // TODO: Remove

/**
 * @typedef {"SHA-256"|"SHA-384"|"SHA-512"} DigestAlgo
 */

/**
 * @typedef {Uint8Array|Uint8ClampedArray|Uint16Array|Uint32Array|Int8Array|Int16Array|Int32Array|Float32Array|Float64Array} TypedArray
 */

/**
 * @typedef {Number[]|TypedArray} NumericArray
 */

/**
 * @typedef {HTMLInputElement|HTMLSelectElement} CustomValidityElement
 */

main();

/**
 * Initializes the application.
 */
function main()
{
    initDiagnostics();
    initDocument();
}

/**
 * Determines whether the user's device is a mobile device.
 * 
 * Tablets are not considered to be mobile devices.
 * 
 * Returns a boolean indicating whether the user's device is a mobile device.
 */
function isMobile()
{
    return (
        (/** @type {any} */ (navigator)).userAgentData &&
        (/** @type {any} */ (navigator)).userAgentData.mobile
    );
}

/**
 * Initializes debug features.
 */
function initDiagnostics()
{
    if(isMobile())
    {
        initMobileDiagnostics();
    }

    addEventListener("error", onErrorEvent);
}

/**
 * Initializes debug features for mobile platforms.
 */
function initMobileDiagnostics()
{
    const activeTimers = new Map();

    console.log = function(...args)
    {
        alert(formatConsoleArguments(args));
    };

    console.warn = console.log;
    console.error = console.log;

    console.time = function(label)
    {
        const now = performance.now();

        if(typeof label != "string")
        {
            label = "default";
        }

        if(activeTimers.has(label))
        {
            console.warn("Label already exists: %s", label);
            return;
        }

        activeTimers.set(label, now);
    };

    console.timeEnd = function(label)
    {
        const now = performance.now();

        if(typeof label != "string")
        {
            label = "default";
        }

        const startTime = activeTimers.get(label);

        if(!activeTimers.delete(label))
        {
            console.warn("Label does not exist: %s", label);
            return;
        }

        console.log("%s: %s ms", label, (now - startTime).toFixed(3));
    };
}

function formatConsoleArguments(args)
{
    if(args.length === 0)
    {
        return "";
    }

    let first = args[0];

    if(args.length === 1)
    {
        return first;
    }

    let pctI = first.indexOf("%");
    let argI = 1;

    while(pctI !== -1 && argI < args.length)
    {
        let converted;

        switch(first.charAt(pctI + 1))
        {
            case "%":
                converted = "%";
                break;
            case "s":
                converted = String(args[argI]);
                break;
            case "d":
            case "i":
                converted = (typeof args[argI] === "symbol") ? NaN : parseInt(args[argI], 10);
                break;
            case "f":
                converted = (typeof args[argI] === "symbol") ? NaN : parseFloat(args[argI]);
                break;
            case "c":
            case "o":
            case "O":
                converted = "UNIMPLEMENTED"; // TODO
                break;
            default:
                // Do nothing
                break;
        }

        if(typeof converted !== "undefined")
        {
            argI++;
            converted = String(converted);
            first = first.substring(0, pctI) + converted + first.substring(pctI + 2);
        }

        pctI = first.indexOf("%", pctI + 1);
    }

    if(argI < args.length)
    {
        first += args.slice(argI).join(", ");
    }

    return first;
}

/**
 * Initializes the contents of the document.
 */
function initDocument()
{
    document.addEventListener("DOMContentLoaded", onDOMContentLoadedEvent);
}

/**
 * Sets up the document on the DOMContentLoaded event.
 * 
 * If the WebCrypto API is unavailable, an error is displayed.
 * 
 * @throws {Error} The WebCrypto API is unavailable.
 */
function onDOMContentLoadedEvent()
{
    if(typeof crypto !== "object" || !crypto || typeof crypto.subtle !== "object" || !crypto.subtle)
    {
        throw new Error("Security features are unavailable.");
    }

    if(typeof navigator.gpu !== "object" || !navigator.gpu)
    {
        throw new Error("GPU computation is unavailable.");
    }

    initWebGpuAsync()
        .then(initForms)
        .catch(onError);
}

/**
 * Asynchronously initializes WebGPU functionality.
 * 
 * @returns {Promise<void>} A promise that resolves when WebGPU functionality has been initialized.
 */
async function initWebGpuAsync()
{
    gpuAdapter = await navigator.gpu.requestAdapter();

    if(!gpuAdapter)
    {
        throw new Error("GPU access is not available.");
    }

    gpuDevice = await gpuAdapter.requestDevice();
    gpuDevice.lost.finally(onWebGpuDeviceLost);
    await initWebGpuComputeShaderAsync(gpuDevice);
}

/**
 * Handles the WebGPU device being lost.
 */
function onWebGpuDeviceLost()
{
    gpuDevice = null;
    gpuNumDeviceLosses++;

    if(gpuNumDeviceLosses >= MAX_ACCEPTABLE_NUMBER_OF_GPU_DEVICE_LOSSES)
    {
        return;
    }

    const oldPromise = gpu_buffer_output2_mapAsync_promise;
    gpu_buffer_output2_mapAsync_promise = initWebGpuAsync()
        .catch(onError);

    if(oldPromise)
    {
        gpu_buffer_output2_mapAsync_promise = gpu_buffer_output2_mapAsync_promise.then(() => oldPromise);
    }
}

/**
 * Asynchronously initializes the WebGPU compute shader for computing hash chains.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
async function initWebGpuComputeShaderAsync(device)
{
    const shaderModule = device.createShaderModule({
        label: COMPUTE_SHADER_MODULE_LABEL,
        code: COMPUTE_SHADER_MODULE_CODE
    });

    const pipelinePromise = device.createComputePipelineAsync({
        label: COMPUTE_SHADER_PIPELINE_LABEL,
        layout: "auto", // TODO: Replace?
        compute: {
            entryPoint: COMPUTE_SHADER_ENTRYPOINT_NAME,
            module: shaderModule
        }
    });

    initWebGpuComputeShaderBuffers(device);
    gpuComputePipeline = await pipelinePromise;
    gpuComputeBindGroup0 = device.createBindGroup({
        label: COMPUTE_SHADER_GROUP0_LABEL,
        layout: gpuComputePipeline.getBindGroupLayout(0),
        entries: [
            {
                binding: COMPUTE_SHADER_GROUP0_BUFFER_INPUT_PROCESS_BINDING,
                resource: {
                    buffer: /** @type {GPUBuffer} */ (gpuGroup0_buffer_input_gpuBuffer),
                    offset: gpuGroup0_buffer_input_process_offset,
                    size: COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_BYTE_LENGTH
                }
            },
            {
                binding: COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BINDING,
                resource: {
                    buffer: /** @type {GPUBuffer} */ (gpuGroup0_buffer_output_gpuBuffer),
                    offset: gpuGroup0_buffer_output_hashes_offset,
                    size: COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BYTE_LENGTH
                }
            }
        ]
    });
}

/**
 * Creates a new array of command buffers for the WebGPU compute shader.
 * 
 * @param {Number} numHashes The number of hashes to compute.
 * @returns {GPUCommandBuffer[]} An array of command buffers.
 */
function createWebGpuComputeShaderCommandBuffers(numHashes)
{
    const encoder = (/** @type {GPUDevice} */ (gpuDevice)).createCommandEncoder();
    const pass = encoder.beginComputePass();

    pass.setPipeline(/** @type {GPUComputePipeline} */ (gpuComputePipeline));
    pass.setBindGroup(0, gpuComputeBindGroup0);
    pass.dispatchWorkgroups(COMPUTE_SHADER_DISPATCH_X, COMPUTE_SHADER_DISPATCH_Y, COMPUTE_SHADER_DISPATCH_Z);
    pass.end();
    encoder.copyBufferToBuffer(
        /** @type {GPUBuffer} */ (gpuGroup0_buffer_output_gpuBuffer),
        gpuGroup0_buffer_output_hashes_offset,
        /** @type {GPUBuffer} */ (gpu_buffer_output2_gpuBuffer), 
        gpu_buffer_output2_hashes_offset,
        COMPUTE_SHADER_HASH_BYTE_LENGTH * numHashes
    );

    return [ encoder.finish() ];
}

/**
 * Initializes the buffers for the WebGPU compute shader.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
function initWebGpuComputeShaderBuffers(device)
{
    initWebGpuComputeShaderGroup0Buffers(device);
    initWebGpuComputeShaderOutput2Buffer(device);
}

/**
 * Initializes the buffers for group 0 of the WebGPU compute shader.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
function initWebGpuComputeShaderGroup0Buffers(device)
{
    initWebGpuComputeShaderGroup0InputBuffer(device);
    initWebGpuComputeShaderGroup0OutputBuffer(device);
}

/**
 * Initializes the input buffer for group 0 of the WebGPU compute shader.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
function initWebGpuComputeShaderGroup0InputBuffer(device)
{
    let offset = 0;

    offset = calculateAlignedAddress(offset, device.limits.minStorageBufferOffsetAlignment);
    gpuGroup0_buffer_input_process_offset = offset;

    // Values in struct
    {
        gpuGroup0_buffer_input_process_numRequests_offset = offset;
        offset += COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_NUM_REQUESTS_BYTE_LENGTH;

        gpuGroup0_buffer_input_process_requests_offset = offset;
        offset += COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_REQUESTS_BYTE_LENGTH;
    }

    // Don't create a new array buffer if we already have one (e.g. after losing a previous GPU device)
    if(!gpuGroup0_buffer_input_arrayBuffer)
    {
        gpuGroup0_buffer_input_arrayBuffer = new ArrayBuffer(offset);
    }

    gpuGroup0_buffer_input_dataView = new DataView(gpuGroup0_buffer_input_arrayBuffer);

    gpuGroup0_buffer_input_gpuBuffer = device.createBuffer({
        label: COMPUTE_SHADER_GROUP0_BUFFER_INPUT_LABEL,
        size: gpuGroup0_buffer_input_arrayBuffer.byteLength,
        usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.STORAGE
    });
}

/**
 * Initializes the output buffer for group 0 of the WebGPU compute shader.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
function initWebGpuComputeShaderGroup0OutputBuffer(device)
{
    let offset = 0;

    offset = calculateAlignedAddress(offset, device.limits.minStorageBufferOffsetAlignment);
    gpuGroup0_buffer_output_hashes_offset = offset;
    offset += COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_HASHES_BYTE_LENGTH;

    gpuGroup0_buffer_output_gpuBuffer = device.createBuffer({
        label: COMPUTE_SHADER_GROUP0_BUFFER_OUTPUT_LABEL,
        size: offset,
        usage: GPUBufferUsage.COPY_SRC | GPUBufferUsage.STORAGE
    });
}

/**
 * Initializes the mappable output buffer for the WebGPU compute shader.
 * 
 * @param {GPUDevice} device The GPU device to use.
 */
function initWebGpuComputeShaderOutput2Buffer(device)
{
    let offset = 0;

    gpu_buffer_output2_hashes_offset = offset;
    offset += COMPUTE_SHADER_BUFFER_OUTPUT2_HASHES_BYTE_LENGTH;

    gpu_buffer_output2_gpuBuffer = device.createBuffer({
        label: COMPUTE_SHADER_BUFFER_OUTPUT2_LABEL,
        size: offset,
        usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
    });
}

/**
 * Sets the next messages and N-values of the WebGPU compute shader.
 * 
 * Note that this does not update the buffer that is used by the GPU.
 * 
 * @see mapWebGpuComputeShaderGroup0InputBuffer
 * @see runWebGpuComputeShaderAsync
 * 
 * @param {ArrayBuffer[]} bufs Promises that resolve to message buffers.
 * @param {Number[]} nValues The N-values of the corresponding message buffers.
 */
function setWebGpuComputeShaderGroup0InputProcessValues(bufs, nValues)
{
    (/** @type {DataView} */ (gpuGroup0_buffer_input_dataView)).setUint32(gpuGroup0_buffer_input_process_numRequests_offset, bufs.length, true);

    for(let i = 0, offset = gpuGroup0_buffer_input_process_requests_offset; i < bufs.length; i++)
    {
        (/** @type {DataView} */ (gpuGroup0_buffer_input_dataView)).setUint32(offset, nValues[i], true);
        offset += COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_N_BYTE_LENGTH;

        copyBufferToBuffer(bufs[i], 0, /** @type {ArrayBuffer} */ (gpuGroup0_buffer_input_arrayBuffer), offset, COMPUTE_SHADER_HASH_BYTE_LENGTH);
        offset += COMPUTE_SHADER_HASH_BYTE_LENGTH;
    }
}

/**
 * Sends the current contents of input array buffer to the corresponding WebGPU buffer.
 * 
 * @see setWebGpuComputeShaderGroup0InputProcessValues
 * @see runWebGpuComputeShaderAsync
 * 
 * @param {Number} numHashes The number of hashes to compute.
 */
function mapWebGpuComputeShaderGroup0InputBuffer(numHashes)
{
    const byteLength =
        COMPUTE_SHADER_STRUCT_CHAIN_PROCESS_NUM_REQUESTS_BYTE_LENGTH +
        COMPUTE_SHADER_STRUCT_CHAIN_REQUEST_BYTE_LENGTH * numHashes;

    (/** @type {GPUDevice} */ (gpuDevice)).queue.writeBuffer(
        /** @type {GPUBuffer} */ (gpuGroup0_buffer_input_gpuBuffer),
        gpuGroup0_buffer_input_process_numRequests_offset,
        /** @type {ArrayBuffer} */ (gpuGroup0_buffer_input_arrayBuffer),
        gpuGroup0_buffer_input_process_numRequests_offset,
        byteLength
    );
}

/**
 * Runs the WebGPU compute shader to compute a value in a hash chain.
 * 
 * @see setWebGpuComputeShaderGroup0InputMessage
 * @see setWebGpuComputeShaderGroup0InputN
 * 
 * @param {Promise<ArrayBuffer>[]} bufPromises Promises that resolve to message buffers.
 * @param {Number[]} nValues The N-values of the corresponding message buffers.
 * @returns {Promise<ArrayBuffer>} The resulting array buffer, where each hash is in sequential order.
 * @throws {ReferenceError} The GPU device has been lost and could not be recovered.
 */
async function runWebGpuComputeShaderAsync(bufPromises, nValues)
{
    while(gpu_buffer_output2_mapAsync_promise)
    {
        await gpu_buffer_output2_mapAsync_promise; // Wait for any pending computations to finish.
    }

    const bufs = await Promise.all(bufPromises);
    const numBufs = bufs.length; // For early GC of buffers
    assertWebGpuDeviceAvailability();
    setWebGpuComputeShaderGroup0InputProcessValues(bufs, nValues);
    mapWebGpuComputeShaderGroup0InputBuffer(numBufs);
    const cmdBufs = createWebGpuComputeShaderCommandBuffers(numBufs);
    (/** @type {GPUDevice} */ (gpuDevice)).queue.submit(cmdBufs);

    gpu_buffer_output2_mapAsync_promise = (/** @type {GPUBuffer} */ (gpu_buffer_output2_gpuBuffer)).mapAsync(
        GPUMapMode.READ,
        gpu_buffer_output2_hashes_offset,
        COMPUTE_SHADER_HASH_BYTE_LENGTH * numBufs
    );
    assertWebGpuDeviceAvailability();
    await gpu_buffer_output2_mapAsync_promise;
    gpu_buffer_output2_mapAsync_promise = null;

    const hashes = (/** @type {GPUBuffer} */ (gpu_buffer_output2_gpuBuffer)).getMappedRange(
        gpu_buffer_output2_hashes_offset,
        COMPUTE_SHADER_HASH_BYTE_LENGTH * numBufs
    ).slice(0);

    (/** @type {GPUBuffer} */ (gpu_buffer_output2_gpuBuffer)).unmap();
    assertWebGpuDeviceAvailability();
    return hashes;
}

/**
 * Asserts that the WebGPU device is available.
 * 
 * @throws {ReferenceError} The GPU device has been lost.
 */
function assertWebGpuDeviceAvailability()
{
    if(!gpuDevice)
    {
        throw new ReferenceError("The GPU is unavailable.");
    }
}

/**
 * Calculates the lowest-possible address that is aligned to a given number of bytes.
 * 
 * @param {Number} minAddr The lowest address that can be returned by this function.
 * @param {Number} alignTo The number of bytes to align the address to.
 * @returns {Number} The address, which is no lower than `minAddr` and is aligned to a size of `alignTo` bytes.
 * @throws {RangeError} The given minimum address is a negative integer.
 * @throws {RangeError} The given alignment size is a non-positive integer.
 * @throws {TypeError} The given minimum address is not an integer.
 * @throws {TypeError} The given alignment size is not an integer.
 */
function calculateAlignedAddress(minAddr, alignTo)
{
    if(!Number.isInteger(minAddr))
    {
        throw new TypeError("Minimum address is not an integer!");
    }

    if(minAddr < 0)
    {
        throw new RangeError("Minimum address is negative!");
    }

    if(!Number.isInteger(alignTo))
    {
        throw new TypeError("Alignment size is not an integer!");
    }

    if(alignTo < 1)
    {
        throw new RangeError("Alignment size is not positive!");
    }

    const mod = minAddr % alignTo;
    return (mod === 0) ? minAddr : (minAddr + alignTo - mod);
}

/**
 * Initializes the forms in the document.
 */
function initForms()
{
    initGeneratePublicKeyForm();
    initGenerateSignatureForm();
    initVerifyForm();
}

/**
 * Initializes the form for generating a public key.
 */
function initGeneratePublicKeyForm()
{
    /** @type {HTMLFormElement} */
    const form = document.forms[FORM_GENERATE_PUBLIC_KEY_NAME];
    form.addEventListener("submit", onGeneratePublicKeyFormSubmitEvent);
    form.elements[FORM_GENERATE_PUBLIC_KEY_ELEMENT_SUBMIT_NAME].disabled = false;
}

/**
 * Initializes the form for generating a signature.
 */
function initGenerateSignatureForm()
{
    /** @type {HTMLFormElement} */
    const form = document.forms[FORM_GENERATE_SIGNATURE_NAME];
    form.addEventListener("submit", onGenerateSignatureFormSubmitEvent);
    initCustomValidityElement(form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_MASTER_KEY_NAME]);
    initCustomValidityElement(form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_CONTENT_HASH_NAME]);
    form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_SUBMIT_NAME].disabled = false;
}

/**
 * Initializes the form for verifying a signature.
 */
function initVerifyForm()
{
    /** @type {HTMLFormElement} */
    const form = document.forms[FORM_VERIFY_NAME];
    form.addEventListener("submit", onVerifyFormSubmitEvent);
    initCustomValidityElement(form.elements[FORM_VERIFY_ELEMENT_PUBLIC_KEY_NAME]);
    initCustomValidityElement(form.elements[FORM_VERIFY_ELEMENT_SIGNATURE_NAME]);
    initCustomValidityElement(form.elements[FORM_VERIFY_ELEMENT_CONTENT_HASH_NAME]);
    form.elements[FORM_VERIFY_ELEMENT_SUBMIT_NAME].disabled = false;
}

/**
 * Adds event handlers for custom validity messages.
 * 
 * @param {CustomValidityElement} elem The element to display custom validity messages for.
 * @param {(CustomValidityElement)[]|null} validityBindings An array of elements that remove `elem`'s custom validity message upon input.
 */
function initCustomValidityElement(elem, validityBindings = null)
{
    elem.addEventListener("input", onCustomValidityElementInputEvent);

    if(validityBindings)
    {
        const onCustomValidityBoundInputEvent = () => { clearCustomValidity(elem); };

        for(let i = 0; i < validityBindings.length; i++)
        {
            validityBindings[i].addEventListener("input", onCustomValidityBoundInputEvent);
        }
    }
}

/**
 * Event handler that clears the custom validity message for an element.
 * @see initCustomValidityElement
 * 
 * @param {Event} event The event.
 */
function onCustomValidityElementInputEvent(event)
{
    clearCustomValidity(/** @type {CustomValidityElement} */ (event.currentTarget));
}

/**
 * Removes the custom validity message (if any) from an element.
 * @see initCustomValidityElement
 * 
 * @param {CustomValidityElement} elem 
 */
function clearCustomValidity(elem)
{
    elem.setCustomValidity("");
}

/**
 * Sets the custom validity message for an element, and displays it if told to.
 * Elements that use this function should be initialized with `initCustomValidityElement`.
 * @see initCustomValidityElement
 * 
 * @param {CustomValidityElement} elem The element to set the custom validity message of.
 * @param {String} errorMessage The validity message to set.
 * @param {Boolean} doReport A boolean indicating whether the validity message should be displayed immediately.
 */
function setCustomValidity(elem, errorMessage, doReport)
{
    elem.setCustomValidity(errorMessage);

    if(doReport)
    {
        elem.reportValidity();
    }
}

/**
 * Handles the "submit" event for the public key generation form.
 * 
 * @param {SubmitEvent} event The "submit" event.
 */
function onGeneratePublicKeyFormSubmitEvent(event)
{
    event.preventDefault();
    processGeneratePublicKeyForm(/** @type {HTMLFormElement} */ (event.currentTarget));
}

/**
 * Handles the "submit" event for the signature generation form.
 * 
 * @param {SubmitEvent} event The "submit" event.
 */
function onGenerateSignatureFormSubmitEvent(event)
{
    event.preventDefault();
    processGenerateSignatureForm(/** @type {HTMLFormElement} */ (event.currentTarget));
}

/**
 * Handles the "submit" event for the signature verification form.
 * 
 * @param {SubmitEvent} event The "submit" event.
 */
function onVerifyFormSubmitEvent(event)
{
    event.preventDefault();
    processVerifyForm(/** @type {HTMLFormElement} */ (event.currentTarget));
}

/**
 * Generates a public key for a given public key generation form.
 * 
 * The form will be disabled while the public key is being generated.
 * 
 * @param {HTMLFormElement} form The public key generation form.
 */
function processGeneratePublicKeyForm(form)
{
    const PERFORMANCE_TIMER_NAME = "Public key generation";
    form.elements[FORM_GENERATE_PUBLIC_KEY_ELEMENT_SUBMIT_NAME].disabled = true;

    console.time(PERFORMANCE_TIMER_NAME);
    processGeneratePublicKeyFormElementsAsync(form)
        .finally(() => { console.timeEnd(PERFORMANCE_TIMER_NAME); }) // Before catch so the timer isn't affected by any error handling
        .catch(onError)
        .finally(
            () =>
            {
                form.elements[FORM_GENERATE_PUBLIC_KEY_ELEMENT_SUBMIT_NAME].disabled = false;
            }
        );
}

/**
 * Generates a signature for a given signature generation form.
 * 
 * The form will be disabled while the signature is being generated.
 * 
 * @param {HTMLFormElement} form The signature generation form.
 */
function processGenerateSignatureForm(form)
{
    const PERFORMANCE_TIMER_NAME = "Signature generation";
    form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_SUBMIT_NAME].disabled = true;

    console.time(PERFORMANCE_TIMER_NAME);
    processGenerateSignatureFormElementsAsync(form)
        .finally(() => { console.timeEnd(PERFORMANCE_TIMER_NAME); }) // Before catch so the timer isn't affected by any error handling
        .catch(onError)
        .finally(
            () =>
            {
                form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_SUBMIT_NAME].disabled = false;
            }
        );
}

/**
 * Verifies a signature for a given signature verification form.
 * 
 * The form will be disabled while the signature is being verified.
 * 
 * @param {HTMLFormElement} form The signature verification form.
 */
function processVerifyForm(form)
{
    const PERFORMANCE_TIMER_NAME = "Signature verification";
    form.elements[FORM_VERIFY_ELEMENT_SUBMIT_NAME].disabled = true;

    console.time(PERFORMANCE_TIMER_NAME);
    processVerifyFormElementsAsync(form)
        .finally(() => { console.timeEnd(PERFORMANCE_TIMER_NAME); }) // Before catch so the timer isn't affected by any error handling
        .catch(onError)
        .finally(
            () =>
            {
                form.elements[FORM_VERIFY_ELEMENT_SUBMIT_NAME].disabled = false;
            }
        );
}

/**
 * Asynchronously generates a public key for a given public key generation form.
 * 
 * This function is called by `processGeneratePublicKeyForm`.
 * @see processGeneratePublicKeyForm
 * 
 * Once the public key is generated, the data will be output to the document using `outputGeneratePublicKeyValues`.
 * @see outputGeneratePublicKeyValues
 * 
 * @param {HTMLFormElement} form The public key generation form.
 * @returns {Promise<void>} A promise that resolves once public key generation is complete and the results have been output.
 * @throws {null} An error which does not require further handling has occurred.
 * @throws {Error} A sanity check failed to pass.
 */
async function processGeneratePublicKeyFormElementsAsync(form)
{
    TEMP_digestOpCount = 0; // TODO: Remove

    // Retrieve form elements before async goes into effect
    /** @type {HTMLInputElement} */
    const formMasterKeyInput = form.elements[FORM_GENERATE_PUBLIC_KEY_ELEMENT_MASTER_KEY_NAME];

    // Retrieve form values before async goes into effect
    const masterKeyHex = formMasterKeyInput.value;

    // Validate master key in input form
    /** @type {ArrayBuffer|null} */
    let masterKeyBuf = null;

    try
    {
        masterKeyBuf = hexBytesToUint8Array(masterKeyHex).buffer;
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid master key, so let's focus on that.
        setCustomValidity(formMasterKeyInput, err.message, true);
        throw null;
    }

    // Context setup
    const conf = createSigConfig();

    // Create promises for generating private key values (calculated while other independent tasks run)
    const privateKeyPromises = await derivePrivateKeyFromMasterKey(HASH_SHA256_NAME, HASH_SHA256_BIT_LENGTH, masterKeyBuf, conf.numChains);

    // Generate Merkle trees and obtain the public key
    let publicKeyBuf = null;

    {
        const chainNValues =
            /** @type {number[]} */
            (
                (
                    /** @type {any[]} */
                    (privateKeyPromises)
                )
                .slice()
                .fill(-1)
            );
        let chainI = 0;

        // Checksum
        for(let cni = 0; cni < conf.checksum.numNumerals; cni++)
        {
            chainNValues[chainI] = conf.checksum.maxNumeralValue;
            chainI++;
        }

        // Permutation ID
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            chainNValues[chainI] = conf.group.maxPermutationId;
            chainI++;
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numValues; i++)
            {
                chainNValues[chainI] = conf.group.maxDeltaValue;
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        const chainEndpointsBuf = await digestChains(HASH_SHA256_NAME, privateKeyPromises, chainNValues);
        const chainEndpoints =
            /** @type {(Promise<ArrayBuffer>|null)[]} */
            (
                (
                    /** @type {any[]} */
                    (chainNValues)
                )
                .slice()
                .fill(null)
            );

        for(let i = 0, offset = 0; i < chainEndpoints.length; i++, offset += (HASH_SHA256_BIT_LENGTH / 8))
        {
            chainEndpoints[i] = Promise.resolve(chainEndpointsBuf.slice(offset, offset + (HASH_SHA256_BIT_LENGTH / 8)));
        }

        publicKeyBuf = await calculateMerkleTreeRootFromLeafNodePromises(HASH_SHA256_NAME, /** @type {Promise<ArrayBuffer>[]} */ (chainEndpoints));
    }

    // Done!
    outputGeneratePublicKeyValues(publicKeyBuf);
}

/**
 * Asynchronously generates a signature for a given signature generation form.
 * 
 * This function is called by `processGenerateSignatureForm`.
 * @see processGenerateSignatureForm
 * 
 * Once the signature is generated, the data will be output to the document using `outputGenerateSignatureValues`.
 * @see outputGenerateSignatureValues
 * 
 * @param {HTMLFormElement} form The signature generation form.
 * @returns {Promise<void>} A promise that resolves once signature generation is complete and the results have been output.
 * @throws {null} An error which does not require further handling has occurred.
 * @throws {Error} A sanity check failed to pass.
 */
async function processGenerateSignatureFormElementsAsync(form)
{
    TEMP_digestOpCount = 0; // TODO: Remove

    // Retrieve form elements before async goes into effect
    /** @type {HTMLInputElement} */
    const formMasterKeyInput = form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_MASTER_KEY_NAME];
    /** @type {HTMLInputElement} */
    const formContentHashInput = form.elements[FORM_GENERATE_SIGNATURE_ELEMENT_CONTENT_HASH_NAME];

    // Retrieve form values before async goes into effect
    const masterKeyHex = formMasterKeyInput.value;
    const contentHashHex = formContentHashInput.value;

    // Validate master key in input form
    /** @type {ArrayBuffer|null} */
    let masterKeyBuf = null;

    try
    {
        masterKeyBuf = hexBytesToUint8Array(masterKeyHex).buffer;
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid master key, so let's focus on that.
        setCustomValidity(formMasterKeyInput, err.message, true);
        throw null;
    }

    // Validate content hash in input form
    /** @type {ArrayBuffer|null} */
    let contentHashBuf = null;

    try
    {
        if(contentHashHex.length * 4 !== HASH_SHA256_BIT_LENGTH)
        {
            throw new Error("Invalid number of characters!");
        }

        contentHashBuf = hexBytesToUint8Array(contentHashHex).buffer;
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid content hash, so let's focus on that.
        setCustomValidity(formContentHashInput, err.message, true);
        throw null;
    }

    // Context setup
    const conf = createSigConfig();
    const groups = createSigGroupsBySigConfig(conf, contentHashBuf);

    // Create promises for generating private key values (calculated while other independent tasks run)
    const privateKeyPromises = await derivePrivateKeyFromMasterKey(HASH_SHA256_NAME, HASH_SHA256_BIT_LENGTH, masterKeyBuf, conf.numChains);

    // Calculate chain values
    const checksum = populateSigGroupsBySigConfig(conf, groups);

    // Generate Merkle trees and obtain the signature
    /** @type {ArrayBuffer|null} */
    let signature = null;

    {
        const chainNValues =
            /** @type {number[]} */
            (
                (
                    /** @type {any[]} */
                    (privateKeyPromises)
                )
                .slice()
                .fill(-1)
            );
        let chainI = 0;

        // Checksum
        for(let i = 0, shift = 0; i < conf.checksum.numNumerals; i++, shift += conf.checksum.numeralBaseLog2)
        {
            const numeral = (checksum >>> shift) & conf.checksum.maxNumeralValue;
            chainNValues[chainI] = conf.checksum.maxNumeralValue - numeral;
            chainI++;
        }

        // Permutation ID
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            chainNValues[chainI] = conf.group.maxPermutationId - groups[gi].permutationId;
            chainI++;
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numValues; i++)
            {
                chainNValues[chainI] = conf.group.maxDeltaValue - groups[gi].deltaValues[i];
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        signature = await digestChains(HASH_SHA256_NAME, privateKeyPromises, chainNValues); // These promises should already have resolved, so there's practically no performance penalty.
    }

    // Done!
    outputGenerateSignatureValues(signature, contentHashBuf);
}

/**
 * Asynchronously verifies a signature for a given signature verification form.
 * 
 * This function is called by `processVerifyForm`.
 * @see processVerifyForm
 * 
 * Once the signature is verified, the data will be output to the document using `outputVerifyValues`.
 * @see outputVerifyValues
 * 
 * @param {HTMLFormElement} form The signature verification form.
 * @returns {Promise<void>} A promise that resolves once signature verification is complete and the results have been output.
 * @throws {null} An error which does not require further handling has occurred.
 * @throws {Error} A sanity check failed to pass.
 */
async function processVerifyFormElementsAsync(form)
{
    TEMP_digestOpCount = 0; // TODO: Remove

    // Retrieve form elements before async goes into effect
    /** @type {HTMLInputElement} */
    const formContentHashInput = form.elements[FORM_VERIFY_ELEMENT_CONTENT_HASH_NAME];
    /** @type {HTMLInputElement} */
    const formPublicKeyInput = form.elements[FORM_VERIFY_ELEMENT_PUBLIC_KEY_NAME];
    /** @type {HTMLInputElement} */
    const formSignatureInput = form.elements[FORM_VERIFY_ELEMENT_SIGNATURE_NAME];

    // Retrieve form values before async goes into effect
    const contentHashHex = formContentHashInput.value;
    const publicKeyHex = formPublicKeyInput.value;
    const signatureFile = (/** @type {FileList} */ (formSignatureInput.files))[0];

    // Validate content hash in input form
    /** @type {ArrayBuffer|null} */
    let contentHashBuf = null;

    try
    {
        if(contentHashHex.length * 4 !== HASH_SHA256_BIT_LENGTH)
        {
            throw new Error("Invalid number of characters!");
        }

        contentHashBuf = hexBytesToUint8Array(contentHashHex).buffer;
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid content hash, so let's focus on that.
        setCustomValidity(formContentHashInput, err.message, true);
        throw null;
    }

    // Validate public key in input form
    /** @type {ArrayBuffer|null} */
    let publicKeyBuf = null;

    try
    {
        if(publicKeyHex.length * 4 !== HASH_SHA256_BIT_LENGTH)
        {
            throw new Error("Invalid number of characters!");
        }

        publicKeyBuf = hexBytesToUint8Array(publicKeyHex).buffer;
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid public key, so let's focus on that.
        setCustomValidity(formPublicKeyInput, err.message, true);
        throw null;
    }

    // Begin reading signature from file
    const signatureBufPromise = signatureFile.arrayBuffer();

    // Context setup
    const conf = createSigConfig();
    const groups = createSigGroupsBySigConfig(conf, contentHashBuf);

    // Calculate chain values
    const checksum = populateSigGroupsBySigConfig(conf, groups);

    // Validate signature in input form
    /** @type {Promise<ArrayBuffer>[]} */
    let signatureBufPromises = [ ];

    try
    {
        const signatureBuf = await signatureBufPromise;

        if(signatureBuf.byteLength !== conf.numChains * (HASH_SHA256_BIT_LENGTH / 8))
        {
            throw new Error("Invalid signature!");
        }

        for(let i = 0; i < signatureBuf.byteLength; i += (HASH_SHA256_BIT_LENGTH / 8))
        {
            signatureBufPromises.push(Promise.resolve(signatureBuf.slice(i, i + (HASH_SHA256_BIT_LENGTH / 8))));
        }
    }
    catch(err)
    {
        // Any errors thrown in the `try` block are caused by providing an invalid content hash, so let's focus on that.
        setCustomValidity(formSignatureInput, err.message, true);
        throw null;
    }

    /** @type {ArrayBuffer|null} */
    let derivedPublicKeyBuf = null;

    {
        const chainNValues =
            /** @type {number[]} */
            (
                (
                    /** @type {any[]} */
                    (signatureBufPromises)
                )
                .slice()
                .fill(-1)
            );
        let chainI = 0;

        // Checksum
        for(let i = 0, shift = 0; i < conf.checksum.numNumerals; i++, shift += conf.checksum.numeralBaseLog2)
        {
            const numeral = (checksum >>> shift) & conf.checksum.maxNumeralValue;
            chainNValues[chainI] = numeral;
            chainI++;
        }

        // Permutation ID
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            chainNValues[chainI] = groups[gi].permutationId;
            chainI++;
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numValues; i++)
            {
                chainNValues[chainI] = groups[gi].deltaValues[i];
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        const chainEndpointsBuf = await digestChains(HASH_SHA256_NAME, /** @type {Promise<ArrayBuffer>[]} */ (signatureBufPromises), chainNValues);
        const chainEndpoints =
            /** @type {(Promise<ArrayBuffer>|null)[]} */
            (
                (
                    /** @type {any[]} */
                    (chainNValues)
                )
                .slice()
                .fill(null)
            );

        for(let i = 0, offset = 0; i < chainEndpoints.length; i++, offset += (HASH_SHA256_BIT_LENGTH / 8))
        {
            chainEndpoints[i] = Promise.resolve(chainEndpointsBuf.slice(offset, offset + (HASH_SHA256_BIT_LENGTH / 8)));
        }

        derivedPublicKeyBuf = await calculateMerkleTreeRootFromLeafNodePromises(HASH_SHA256_NAME, /** @type {Promise<ArrayBuffer>[]} */ (chainEndpoints));
    }

    // Done!
    const isPassing = testArrayBufferEquality(publicKeyBuf, derivedPublicKeyBuf);
    outputVerifyValues(isPassing);
}

/**
 * Outputs the data related to a generated public key.
 * 
 * This function is called by `processGeneratePublicKeyFormElementsAsync`.
 * @see processGeneratePublicKeyFormElementsAsync
 * 
 * @param {ArrayBuffer} publicKey The public key.
 */
function outputGeneratePublicKeyValues(publicKey)
{
    // Output public key
    const publicKeyElem = /** @type {HTMLElement} */ (document.getElementById(GENERATE_PUBLIC_KEY_OUTPUT_PUBLIC_KEY_ID));
    publicKeyElem.innerText = arrayBufferToHex(publicKey);

    // Unhide container
    const containerElem = /** @type {HTMLElement} */ (document.getElementById(GENERATE_PUBLIC_KEY_OUTPUT_CONTAINER_ID));
    containerElem.hidden = false;
}

/**
 * Outputs the data related to a generated signature.
 * 
 * This function is called by `processGenerateSignatureFormElementsAsync`.
 * @see processGenerateSignatureFormElementsAsync
 * 
 * @param {ArrayBuffer} signature The signature.
 * @param {ArrayBuffer} hashBuf The content hash.
 */
function outputGenerateSignatureValues(signature, hashBuf)
{
    // Output signature
    const sigTextarea = /** @type {HTMLTextAreaElement} */ (document.getElementById(GENERATE_SIGNATURE_OUTPUT_SIGNATURE_TEXTAREA_ID));
    sigTextarea.value = arrayBufferToHex(signature);

    const sigAnchor = /** @type {HTMLAnchorElement} */ (document.getElementById(GENERATE_SIGNATURE_OUTPUT_SIGNATURE_ANCHOR_ID));

    if(sigAnchor.href)
    {
        URL.revokeObjectURL(sigAnchor.href);
    }

    sigAnchor.download = /** @type {String} */ (sigAnchor.dataset.downloadPattern)
        .replace(GENERATE_SIGNATURE_OUTPUT_SIGNATURE_ANCHOR_DOWNLOAD_PATTERN_CONTENT_HASH_REPLACE, arrayBufferToHex(hashBuf));
    sigAnchor.href = URL.createObjectURL(new Blob([ signature ], { type: "application/octet-stream" }));

    // Unhide container
    const containerElem = /** @type {HTMLElement} */ (document.getElementById(GENERATE_SIGNATURE_OUTPUT_CONTAINER_ID));
    containerElem.hidden = false;
}

/**
 * Outputs the data related to a verified signature.
 * 
 * This function is called by `processVerifyFormElementsAsync`.
 * @see processVerifyFormElementsAsync
 * 
 * @param {Boolean} isPassing A boolean indicating whether the signature was valid.
 */
function outputVerifyValues(isPassing)
{
    // Output status
    const statusPassElem = /** @type {HTMLElement} */ (document.getElementById(VERIFY_OUTPUT_STATUS_PASS_ID));
    const statusFailElem = /** @type {HTMLElement} */ (document.getElementById(VERIFY_OUTPUT_STATUS_FAIL_ID));
    statusPassElem.hidden = !isPassing;
    statusFailElem.hidden = isPassing;

    // Unhide container
    const containerElem = /** @type {HTMLElement} */ (document.getElementById(VERIFY_OUTPUT_CONTAINER_ID));
    containerElem.hidden = false;
}

/**
 * Asynchronously computes a cryptographically-secure hash digest of a given message.
 * 
 * @param {DigestAlgo} algo The hash digest algorithm to use.
 * @param {ArrayBuffer} buf The message to digest.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to a hash digest of the given message.
 */
async function digest(algo, buf)
{
    TEMP_digestOpCount++; // TODO: Remove
    return crypto.subtle.digest(algo, buf);
}

/**
 * Recursively computes the hash digests of given messages a given number of times.
 * 
 * For example, a hash digest that is recursively computed two times is `H(H(buf))`.
 * 
 * The buffers that are returned are always new. If `n` is less than 1, a copy of `buf` will be returned.
 * 
 * @param {DigestAlgo} algo The hash digest algorithm to use.
 * @param {Promise<ArrayBuffer>[]} bufs An array of promises that each resolve to a corresponding message to digest.
 * @param {Number[]} nValues An array containing the number of times to recursively compute the corresponding hash digest.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to an array buffer that contains the recursively-computed hash digests of the given messages.
 * @throws {RangeError} The number of messages and N values do not match.
 * @throws {TypeError} The given hash digest algorithm `algo` is not supported.
 */
async function digestChains(algo, bufs, nValues)
{
    if(algo !== HASH_SHA256_NAME)
    {
        throw new TypeError("Invalid hash digest algorithm!");
    }

    if(bufs.length !== nValues.length)
    {
        throw new RangeError("Unequal number of messages and N-values!");
    }

    TEMP_digestOpCount += sumArrayValues(nValues, 0, nValues.length); // TODO: Remove
    return runWebGpuComputeShaderAsync(bufs, nValues);
}

/**
 * Calculates the factorial of a number.
 * 
 * Only non-negative integers are supported.
 * 
 * @param {Number} n The operand of the factorial operation.
 * @returns {Number} The factorial of `n` (i.e. `n!`).
 */
function factorial(n)
{
    let fac = 1;

    while(n > 1)
    {
        fac *= n;
        n--;
    }

    return fac;
}

/**
 * Calculates the sum of the integers in the range [0, `n`].
 * 
 * @param {Number} n The maximum (inclusive) value in the range of integers.
 * @returns {Number} The sum of the integers in the range [0, `n`].
 */
function sumZeroToN(n)
{
    return (n * (n + 1)) >>> 1;
}

/**
 * Calculates the sum of the values in a given array within a given range of indices.
 * 
 * @param {NumericArray} arr The array of values to sum up.
 * @param {Number} start The (inclusive) starting index.
 * @param {Number} end The (exclusive) ending index.
 * @returns {Number} The sum of the numbers in `arr` at indices in the given range.
 */
function sumArrayValues(arr, start, end)
{
    let sum = 0;

    for(let i = start; i < end; i++)
    {
        sum += arr[i];
    }

    return sum;
}

/**
 * Retrieves the largest number within an array of numbers.
 * 
 * @param {NumericArray} arr The array of numbers to search within.
 * @returns {Number} The largest number within the array.
 * @throws {RangeError} The array has a length of zero.
 */
function getLargestValue(arr)
{
    if(arr.length < 1)
    {
        throw new RangeError("Cannot retrieve largest value of empty array!");
    }

    let largest = arr[0];

    for(let i = 1; i < arr.length; i++)
    {
        largest ^= (largest ^ arr[i]) * Number(arr[i] > largest);
    }

    return largest;
}

/**
 * Determines the index that a value within a given array would have if the array were to be sorted numerically from least to greatest.
 * 
 * Equal numbers are ordered based on their indices within the unsorted array; the lower the index, the lower the resulting index.
 * 
 * @param {NumericArray} unsorted The array of unsorted numbers.
 * @param {Number} startIdx The index of to start sorting at (inclusive).
 * @param {Number} unsortedIdx The index of the number within the unsorted array.
 * @param {Number} endIdx The index of to stop sorting at (exclusive).
 * @returns {Number} The index that the number would be located at if the contents of the given array were sorted.
 */
function getIndexInSortedArray(unsorted, startIdx, unsortedIdx, endIdx)
{
    let sortedIdx = 0;

    for(let i = startIdx; i < endIdx; i++)
    {
        sortedIdx +=
        (
            Number(unsorted[i] < unsorted[unsortedIdx]) |
            (
                Number(unsorted[i] === unsorted[unsortedIdx]) &
                Number(i < unsortedIdx)
            )
        );
    }

    return sortedIdx;
}

/**
 * Calculates the delta indices of a given unsorted array of numbers.
 * 
 * @param {NumericArray} nums The unsorted array of numbers.
 * @param {NumericArray|null} deltaIndicesDest The array to place the delta indices in. If provided, the length must not be less than `nums.length`. If not provided, a copy of `nums` will be used.
 * @returns {NumericArray} The array of delta indices. A number at index `i` indicates the index at which `nums[i]`'s corresponding delta value should be placed.
 * @throws {RangeError} The given array of delta indices is too short to fit every delta index of `nums`.
 */
function getDeltaIndices(nums, deltaIndicesDest = null)
{
    if(!deltaIndicesDest)
    {
        deltaIndicesDest = nums.slice();
    }
    else if(deltaIndicesDest.length < nums.length)
    {
        throw new RangeError("Delta indices destination array is too short!");
    }

    for(let i = 0; i < nums.length; i++)
    {
        deltaIndicesDest[i] = getIndexInSortedArray(nums, 0, i, nums.length);
    }

    return deltaIndicesDest;
}

/**
 * Calculates the delta values of a given unsorted array of numbers.
 * @see getDeltaIndices
 * 
 * @param {NumericArray} nums The unsorted array of numbers.
 * @param {NumericArray} deltaIndices The delta indices of `nums`.
 * @param {NumericArray|null} deltaValuesDest The array to place the delta values in. If provided, the length must not be less than `nums.length`. If not provided, a copy of `nums` will be used.
 * @returns {NumericArray} The array of delta values. A number at index `i` indicates the index at which `nums[j]`'s corresponding delta value should be placed, where `j` is the index at which `deltaIndices[j] = i`.
 * @throws {RangeError} The two required arrays (`nums` and `deltaIndices`) have unequal lengths.
 * @throws {RangeError} The given array of delta values is too short to fit every delta value of `nums`.
 */
function getDeltaValues(nums, deltaIndices, deltaValuesDest = null)
{
    if(nums.length !== deltaIndices.length)
    {
        throw new RangeError("The two given arrays must be of equal length!");
    }

    if(!deltaValuesDest)
    {
        deltaValuesDest = nums.slice();
    }
    else if(deltaValuesDest.length < nums.length)
    {
        throw new RangeError("Delta values destination array is too short!");
    }

    // First, place the sorted numbers (which are not differences yet)
    for(let i = 0; i < nums.length; i++)
    {
        deltaValuesDest[deltaIndices[i]] = nums[i];
    }

    // Now calculate the differences
    for(let i = 0, deltaValue = 0, prevSortedValue = 0; i < deltaIndices.length; i++)
    {
        // We have to use this awkward ordering so that we don't set the previous sorted number to the current delta value (which is a difference, not a sorted value)
        deltaValue = deltaValuesDest[i] - prevSortedValue;
        prevSortedValue = deltaValuesDest[i];
        deltaValuesDest[i] = deltaValue;
    }

    return deltaValuesDest;
}

/**
 * Calculates a permutation ID for an array of delta indices.
 * 
 * This function is used to calculate a permutation ID for a signature's delta indices.
 * @see getDeltaIndices
 * @see calculatePermutationIdFromChoices
 * 
 * @param {NumericArray} deltaIndices The delta indices to use.
 * @returns {Number} The permutation ID of the delta indices.
 * @throws {RangeError} The number of delta values/indices is greater than the number of delta indices provided.
 */
function calculatePermutationIdFromDeltaIndices(deltaIndices)
{
    let id = 0;

    for(let i = 0; i < deltaIndices.length; i++)
    {
        id = id * (deltaIndices.length - i) + getIndexInSortedArray(deltaIndices, i, i, deltaIndices.length);
    }

    return id;
}

/**
 * Asynchronously derives a private key based on a given master key.
 * 
 * @param {DigestAlgo} algo The hash digest algorithm to use.
 * @param {Number} algoBitLength The bit-length of the hash digests produced by the `algo` algorithm.
 * @param {ArrayBuffer} masterKeyBuf The master key to use.
 * @param {Number} numValues The number of values in the private key.
 * @returns {Promise<Promise<ArrayBuffer>[]>} A promise that resolves to an array of promises that each resolve to their respective private key value. 
 */
async function derivePrivateKeyFromMasterKey(algo, algoBitLength, masterKeyBuf, numValues)
{
    const masterKey = await crypto.subtle.importKey(
        "raw",
        masterKeyBuf,
        "HKDF",
        false,          // Not extractable
        ["deriveBits"]  // Can only be used to derive bits
    );

    const saltArr = new Uint8Array(algoBitLength / 8);
    //crypto.getRandomValues(saltArr); // TODO: Implement a way to deterministically generate a salt

    const infoView = new DataView(new ArrayBuffer(2));
    /** @type {Promise<ArrayBuffer>[]} */
    const privateKeyPromises = new Array(numValues).fill(null);

    for(let i = 0; i < privateKeyPromises.length; i++)
    {
        infoView.setUint16(0, i, true);
        privateKeyPromises[i] = crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: algo,
                salt: saltArr,
                info: infoView
            },
            masterKey,
            algoBitLength
        )
    }

    return privateKeyPromises;
}

/**
 * Asynchronously computes the digest of the root node of a Merkle tree.
 * 
 * @param {DigestAlgo} algo The hash digest algorithm to use.
 * @param {Promise<ArrayBuffer>[]} leafNodePromises An array of promises that resolve to hash digests, each of which represents a leaf node, in order of left to right.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to the hash digest of the root node of the Merkle tree.
 */
async function calculateMerkleTreeRootFromLeafNodePromises(algo, leafNodePromises)
{
    const level = leafNodePromises.slice();
    let levelLength = level.length;

    while(levelLength > 1)
    {
        for(let i = 0, max = levelLength & ~1; i < max; i += 2)
        {
            level[i >>> 1] = Promise.all(level.slice(i, i + 2))
                .then(childBufs => digest(algo, concatenateArrayBuffers(childBufs)));
        }

        let nextLevelLength = (levelLength + 1) >>> 1; // Divide by two, rounding up

        /* 
        If the current level has an odd number of nodes, we need to copy the last node to the last spot in the next level.
        Here's how to do that without a conditional branch:

        1. Copy the last node in the next level to the index of the last or second-to-last node in the current level if
           the current level has an even or odd number of nodes, respectively.
        2. Copy the last node in the current level - which was replaced during the previous step if the current level has
           an even number of nodes - to the index of the last node in the next level.
        */
        level[levelLength - 1 - (levelLength & 1)] = level[nextLevelLength - 1];
        level[nextLevelLength - 1] = level[levelLength - 1];

        levelLength = nextLevelLength;
    }

    return level[0];
}

/**
 * Converts a string of hexadecimal values to a `Uint8Array` of said values.
 * 
 * Both lowercase and uppercase hexadecimal values are recognized.
 * 
 * @param {String} hex The string of hexadecimal values to convert.
 * @returns {Uint8Array} A typed array of bytes obtained from the given hexadecimal value.
 * @throws {RangeError} The number of hexadecimal values is not a multiple of two.
 * @throws {SyntaxError} An invalid hexadecimal character was encountered.
 */
function hexBytesToUint8Array(hex)
{
    if(hex.length % 2 !== 0)
    {
        throw new RangeError("Only an even number of hexadecimal numerals can be provided!");
    }

    const arr = new Uint8Array(hex.length / 2);
    hex = hex.toLowerCase();

    for(let hexI = 0, alphI = 0, arrI = 0, lshift = 4; hexI < hex.length; hexI++, arrI = (hexI >>> 1), lshift ^= 4)
    {
        alphI = HEX_ALPHABET_LOWERCASE.indexOf(hex[hexI]);

        if(alphI === -1)
        {
            throw new SyntaxError("Invalid hexadecimal digit: " + hex[hexI]);
        }

        arr[arrI] |= (alphI << lshift);
    }

    return arr;
}

/**
 * Converts a buffer to a hexadecimal string.
 * 
 * The hexadecimal characters are in lowercase.
 * 
 * @param {ArrayBuffer} buf The buffer to convert.
 * @returns {String} The hexadecimal string obtained from the given buffer.
 */
function arrayBufferToHex(buf)
{
    let hex = "";
    const arr = new Uint8Array(buf);

    for(let arrI = 0; arrI < arr.length; arrI++)
    {
        hex += arr[arrI].toString(16).toLowerCase().padStart(2, "0");
    }

    return hex;
}

/**
 * Copies the contents of one array buffer to another.
 * 
 * @param {ArrayBuffer} src The array buffer to copy the contents of.
 * @param {Number} srcOffset The offset within `src` to copy the contents of.
 * @param {ArrayBuffer} dest The array buffer to copy the contents of `src` to.
 * @param {Number} destOffset The offset within `dest` to copy the contents of `src` to.
 * @param {Number} length The number of bytes to copy.
 */
function copyBufferToBuffer(src, srcOffset, dest, destOffset, length)
{
    new Uint8Array(dest, destOffset, length).set(new Uint8Array(src, srcOffset, length));
}

/**
 * Tests if the contents of two buffers are equal.
 * 
 * Two buffers are equal if they both have the same length and the byte contents of each buffer are equal in value.
 * 
 * @param {ArrayBuffer} aBuf The first buffer to compare.
 * @param {ArrayBuffer} bBuf The second buffer to compare.
 * @returns {Boolean} A boolean indicating whether the two given buffers have equal contents.
 */
function testArrayBufferEquality(aBuf, bBuf)
{
    if(aBuf.byteLength !== bBuf.byteLength)
    {
        return false;
    }

    const aArr = new Uint8Array(aBuf);
    const bArr = new Uint8Array(bBuf);

    for(let i = 0; i < aArr.length; i++)
    {
        if(aArr[i] !== bArr[i])
        {
            return false;
        }
    }

    return true;
}

/**
 * Concatenates a given array of buffers into one buffer. Order is preserved.
 * 
 * @param {ArrayBuffer[]} bufs The buffers to concatenate. If this array is empty, the returned buffer will have a byte-length of zero.
 * @returns {ArrayBuffer} A buffer containing the contents of the given buffers.
 */
function concatenateArrayBuffers(bufs)
{
    let byteLength = 0;

    for(let i = 0; i < bufs.length; i++)
    {
        byteLength += bufs[i].byteLength;
    }

    const arr = new Uint8Array(byteLength);

    for(let i = 0, addr = 0, partArr = null; i < bufs.length; addr += bufs[i].byteLength, i++)
    {
        partArr = new Uint8Array(bufs[i]);
        arr.set(partArr, addr);
    }

    return arr.buffer;
}

/**
 * Provides a promise that resolves after a given number of milliseconds.
 * 
 * This function uses the built-in `setTimeout` function.
 * 
 * @param {Number} ms The number of milliseconds to wait before the returned promise resolves.
 * @returns {Promise<void>} A promise that resolves after the given number of milliseconds.
 */
function waitAsync(ms)
{
    return new Promise(
        onSuccess =>
        {
            setTimeout(onSuccess, ms);
        }
    );
}

/**
 * Handles an "error" event.
 * @see onError
 * 
 * @param {ErrorEvent} event The "error" event.
 */
function onErrorEvent(event)
{
    onError(event.error);
}

/**
 * Handles an error by logging it and then displaying it via `alert`.
 * 
 * @param {Error|null} err The error to display. If the error is null, this function does nothing.
 */
function onError(err)
{
    if(!err)
    {
        return;
    }

    console.error(err);
    alert(err);
}

/**
 * Creates a new signature configuration object.
 * 
 * @returns {SigConfig} The signature configuration.
 */
function createSigConfig()
{
    const conf = new SigConfig();
    conf.numValues = HASH_SHA256_BIT_LENGTH / 8;
    conf.group = createSigGroupConfig(4);
    conf.numGroups = conf.numValues / conf.group.numValues;
    conf.checksum = createSigChecksumConfig(conf.group.maxChecksum * conf.numGroups);
    conf.numChains =
        conf.group.numChains * conf.numGroups +
        conf.checksum.numNumerals;

    return conf;
}

/**
 * Creates a new signature group configuration object.
 * 
 * @param {Number} numValues The number of values per group.
 * @returns {SigGroupConfig} The signature group configuration.
 */
function createSigGroupConfig(numValues)
{
    const gconf = new SigGroupConfig();
    gconf.numValues = numValues;
    gconf.numChains =
        gconf.numValues + // Delta values
        1; // Permutation ID

    gconf.maxDeltaIndex = gconf.numValues - 1;
    gconf.maxDeltaValue = 255;
    gconf.maxPermutationId = factorial(gconf.numValues) - 1;
    gconf.maxChecksum =
        gconf.maxDeltaValue + // Final delta value
        gconf.maxPermutationId; // Permutation ID

    return gconf;
}

/**
 * Creates a new signature checksum configuration object.
 * 
 * @param {Number} maxValue The maximum checksum value.
 * @returns {SigChecksumConfig} The signature checksum configuration.
 */
function createSigChecksumConfig(maxValue)
{
    const cconf = new SigChecksumConfig();
    cconf.maxValue = maxValue;
    cconf.numNumerals = 2;
    cconf.numeralBaseLog2 = Math.floor((31 - Math.clz32(cconf.maxValue) + cconf.numNumerals) / cconf.numNumerals); // Round up (could use ceil, but not going to for porting purposes)
    cconf.numeralBase = 1 << cconf.numeralBaseLog2;
    cconf.maxNumeralValue = cconf.numeralBase - 1;
    return cconf;
}

/**
 * Creates a SigGroup for a given values array.
 * @param {NumericArray} values The values for this group.
 * @returns {SigGroup} The signature group.
 */
function createSigGroup(values)
{
    const group = new SigGroup();
    group.values = values;
    group.deltaValues = group.values.slice().fill(0);
    group.deltaIndices = group.deltaValues.slice();
    return group;
}

/**
 * Creates an array of SigGroup objects for a given signature configuration and a given hash buffer.
 * 
 * Note that the values of each group are initialized with the proper contents, but all other properties are zeroed-out.
 * @see populateSigGroupsBySigConfig
 * 
 * @param {SigConfig} config The signature configuration.
 * @param {ArrayBuffer} hashBuf A buffer of the hash contents.
 * @returns {SigGroup[]} The array of signature groups.
 */
function createSigGroupsBySigConfig(config, hashBuf)
{
    const groups = [ ];

    for(let i = 0, chi = 0; i < config.numGroups; i++, chi += config.group.numValues)
    {
        groups.push(createSigGroup(new Uint8Array(hashBuf, chi, config.group.numValues)));
    }

    return groups;
}

/**
 * Calculates and sets the proper values for a signature's groups based on its signature configuration, and returns the checksum of said groups.
 * 
 * Specifically, this function sets the delta indices, delta values, and permutation ID of each group. The checksum is calculated and returned.
 * 
 * Each group's values must already be initialized with the proper values.
 * @see createSigGroupsBySigConfig
 * 
 * @param {SigConfig} config The signature configuration.
 * @param {SigGroup[]} groups The signature groups.
 * @returns {Number} The checksum of the signature groups.
 * @throws {Error} The delta indices are invalid.
 * @throws {Error} The delta values are invalid.
 */
function populateSigGroupsBySigConfig(config, groups)
{
    let checksum = 0;

    for(let i = 0; i < config.numGroups; i++)
    {
        getDeltaIndices(groups[i].values, groups[i].deltaIndices);
        getDeltaValues(groups[i].values, groups[i].deltaIndices, groups[i].deltaValues);
        groups[i].permutationId = calculatePermutationIdFromDeltaIndices(groups[i].deltaIndices);
        checksum +=
            (config.group.maxDeltaValue - getLargestValue(groups[i].values)) +
            (config.group.maxPermutationId - groups[i].permutationId);

        if(sumArrayValues(groups[i].deltaIndices, 0, config.group.numValues) !== sumZeroToN(config.group.maxDeltaIndex))
        {
            throw new Error("Invalid delta indices!");
        }
    
        if(sumArrayValues(groups[i].deltaValues, 0, config.group.numValues) !== getLargestValue(groups[i].values))
        {
            throw new Error("Invalid delta values!");
        }
    }

    return checksum;
}

class SigConfig
{
    numValues = -1;
    numGroups = -1;
    /** @type {SigGroupConfig} */
    group = (/** @type {SigGroupConfig} */ (/** @type {any} */ null));
    /** @type {SigChecksumConfig} */
    checksum = (/** @type {SigChecksumConfig} */ (/** @type {any} */ null));

    numChains = -1;
}

class SigGroupConfig
{
    numValues = -1;
    numChains = -1;

    maxDeltaIndex = -1;
    maxDeltaValue = -1;
    maxPermutationId = -1;
    maxChecksum = -1;
}

class SigChecksumConfig
{
    maxValue = -1;
    numNumerals = -1;
    numeralBase = -1;
    numeralBaseLog2 = -1;
    maxNumeralValue = -1;
}

class SigGroup
{
    /** @type {NumericArray} */
    values = null;
    /** @type {NumericArray} */
    deltaIndices = null;
    /** @type {NumericArray} */
    deltaValues = null;
    permutationId = -1;
}
