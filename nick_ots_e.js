"use strict";

// TODO: Consider mixing in some extra data regarding the parameter set (PRF, maybe more?).

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

// Hash function properties
/** @type {DigestAlgo} */
const HASH_SHA256_NAME = "SHA-256";
const HASH_SHA256_BIT_LENGTH = 256;

// Misc.
const HEX_ALPHABET_LOWERCASE = "0123456789abcdef";

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

    initForms();
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
        const publicKeyLeafNodePromises =
            /** @type {(Promise<ArrayBuffer>|null)[]} */
            (
                (
                    /** @type {any[]} */
                    (privateKeyPromises)
                )
                .slice()
                .fill(null)
            );
        let chainI = 0;

        // Checksum
        for(let cni = 0; cni < conf.checksum.numNumerals; cni++)
        {
            publicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.checksum.maxNumeralValue);
            chainI++;
        }

        // Permutation ID
        if(conf.group.hasPermutationId)
        {
            for(let gi = 0; gi < conf.numGroups; gi++)
            {
                publicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.group.maxPermutationId);
                chainI++;
            }
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numDeltaIndices; i++)
            {
                publicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.group.maxDeltaValue);
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        publicKeyBuf = await calculateMerkleTreeRootFromLeafNodePromises(HASH_SHA256_NAME, /** @type {Promise<ArrayBuffer>[]} */ (publicKeyLeafNodePromises));
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
    /** @type {ArrayBuffer[]|null} */
    let sigChainBufs = null;

    {
        const sigChainValuePromises =
            /** @type {(Promise<ArrayBuffer>|null)[]} */
            (
                (
                    /** @type {any[]} */
                    (privateKeyPromises)
                )
                .slice()
                .fill(null)
            );
        let chainI = 0;

        // Checksum
        for(let i = 0, shift = 0; i < conf.checksum.numNumerals; i++, shift += conf.checksum.numeralBaseLog2)
        {
            const numeral = (checksum >>> shift) & conf.checksum.maxNumeralValue;
            sigChainValuePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.checksum.maxNumeralValue - numeral);
            chainI++;
        }

        // Permutation ID
        if(conf.group.hasPermutationId)
        {
            for(let gi = 0; gi < conf.numGroups; gi++)
            {
                sigChainValuePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.group.maxPermutationId - groups[gi].permutationId);
                chainI++;
            }
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numDeltaIndices; i++)
            {
                sigChainValuePromises[chainI] = digestChain(HASH_SHA256_NAME, privateKeyPromises[chainI], conf.group.maxDeltaValue - groups[gi].deltaValues[i]);
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        sigChainBufs = await Promise.all(/** @type {Promise<ArrayBuffer>[]} */ (sigChainValuePromises)); // These promises should already have resolved, so there's practically no performance penalty.
    }

    // Concatenate the signature hashes into one buffer
    const signature = concatenateArrayBuffers(sigChainBufs);

    // Done!
    outputGenerateSignatureValues(signature);
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
    /** @type {ArrayBuffer[]} */
    let signatureBufs = [ ];

    try
    {
        const signatureBuf = await signatureBufPromise;

        if(signatureBuf.byteLength !== conf.numChains * (HASH_SHA256_BIT_LENGTH / 8))
        {
            throw new Error("Invalid signature!");
        }

        for(let i = 0; i < signatureBuf.byteLength; i += (HASH_SHA256_BIT_LENGTH / 8))
        {
            signatureBufs.push(signatureBuf.slice(i, i + (HASH_SHA256_BIT_LENGTH / 8)));
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
        const derivedPublicKeyLeafNodePromises =
            /** @type {(Promise<ArrayBuffer>|null)[]} */
            (
                (
                    /** @type {any[]} */
                    (signatureBufs)
                )
                .slice()
                .fill(null)
            );
        let chainI = 0;

        // Checksum
        for(let i = 0, shift = 0; i < conf.checksum.numNumerals; i++, shift += conf.checksum.numeralBaseLog2)
        {
            const numeral = (checksum >>> shift) & conf.checksum.maxNumeralValue;
            derivedPublicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, signatureBufs[chainI], numeral);
            chainI++;
        }

        // Permutation ID
        if(conf.group.hasPermutationId)
        {
            for(let gi = 0; gi < conf.numGroups; gi++)
            {
                derivedPublicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, signatureBufs[chainI], groups[gi].permutationId);
                chainI++;
            }
        }

        // Delta values
        for(let gi = 0; gi < conf.numGroups; gi++)
        {
            for(let i = 0; i < conf.group.numDeltaIndices; i++)
            {
                derivedPublicKeyLeafNodePromises[chainI] = digestChain(HASH_SHA256_NAME, signatureBufs[chainI], groups[gi].deltaValues[i]);
                chainI++;
            }
        }

        // All done!
        if(chainI !== conf.numChains)
        {
            throw new Error("Incorrect number of chains!");
        }

        derivedPublicKeyBuf = await calculateMerkleTreeRootFromLeafNodePromises(HASH_SHA256_NAME, /** @type {Promise<ArrayBuffer>[]} */ (derivedPublicKeyLeafNodePromises));
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
 */
function outputGenerateSignatureValues(signature)
{
    // Output signature
    const sigTextarea = /** @type {HTMLTextAreaElement} */ (document.getElementById(GENERATE_SIGNATURE_OUTPUT_SIGNATURE_TEXTAREA_ID));
    sigTextarea.value = arrayBufferToHex(signature);

    const sigAnchor = /** @type {HTMLAnchorElement} */ (document.getElementById(GENERATE_SIGNATURE_OUTPUT_SIGNATURE_ANCHOR_ID));

    if(sigAnchor.href)
    {
        URL.revokeObjectURL(sigAnchor.href);
    }

    sigAnchor.download = /** @type {String} */ (sigAnchor.dataset.downloadPattern);
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
 * Recursively computes a hash digest of a given message a given number of times.
 * 
 * For example, a hash digest that is recursively computed two times is `H(H(buf))`.
 * 
 * The buffer that is returned is always new. If `n` is less than 1, a copy of `buf` will be returned.
 * 
 * @param {DigestAlgo} algo The hash digest algorithm to use.
 * @param {ArrayBuffer|Promise<ArrayBuffer>} buf The message to digest, or a promise that resolves to the message to digest.
 * @param {Number} n The number of times to recursively compute the hash digest.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to a recursively-computed hash digest of the given message.
 */
async function digestChain(algo, buf, n)
{
    buf = /** @type {ArrayBuffer} */ (await buf);

    if(n < 1)
    {
        return buf.slice(0);
    }

    while(n > 0)
    {
        buf = await digest(algo, buf);
        n--;
    }

    return buf;
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
 * @param {Number} unsortedIdx The index of the number within the unsorted array.
 * @returns {Number} The index that the number would be located at if the contents of the given array were sorted.
 */
function getIndexInSortedArray(unsorted, unsortedIdx)
{
    let sortedIdx = 0;

    for(let i = 0; i < unsorted.length; i++)
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
        deltaIndicesDest[i] = getIndexInSortedArray(nums, i);
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
 * Calculates an ID that is unique to the ordering of values in an array that represents a "choice."
 * 
 * Each number in `choices` must be a unique integer in the range [0, `choices.length`).
 * 
 * @param {NumericArray} choices An array of numbers that each represent choices. The behavior of this function is undefined when invalid choices are provided.
 * @returns {Number} The ID of the permutation.
 */
function calculatePermutationIdFromChoices(choices)
{
    let id = 0;

    for(let i = 0, j = 0, dec = 0; i < choices.length - 1; i++)
    {
        for(j = 0, dec = 0; j < i; j++)
        {
            dec += Number(choices[j] < choices[i]);
        }

        id = id * (choices.length - i) + (choices[i] - dec);
    }

    return id;
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
    const choices = deltaIndices.slice();

    for(let i = 0; i < deltaIndices.length; i++)
    {
        // We invert the sorted index to "even out" the chain values during verification, which generally speeds up verification done with simultaneous chain calculations.
        choices[i] = (deltaIndices.length - 1) - getIndexInSortedArray(deltaIndices, i);
    }

    return calculatePermutationIdFromChoices(choices);
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
    conf.numGroups = conf.numValues / conf.group.numDeltaIndices;
    conf.checksum = createSigChecksumConfig(conf.group.maxChecksum * conf.numGroups);
    conf.numChains =
        conf.group.numChains * conf.numGroups +
        conf.checksum.numNumerals;

    return conf;
}

/**
 * Creates a new signature group configuration object.
 * 
 * @param {Number} numDeltaIndices The number of delta indices per group.
 * @returns {SigGroupConfig} The signature group configuration.
 */
function createSigGroupConfig(numDeltaIndices)
{
    const gconf = new SigGroupConfig();
    gconf.numDeltaIndices = numDeltaIndices;
    gconf.numChains =
        gconf.numDeltaIndices +
        Number(gconf.hasPermutationId) +
        numDeltaIndices;

    gconf.maxDeltaIndex = gconf.numDeltaIndices - 1;
    gconf.maxDeltaValue = 255;
    gconf.maxPermutationId = factorial(gconf.numDeltaIndices) - 1;
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

    for(let i = 0, chi = 0; i < config.numGroups; i++, chi += config.group.numDeltaIndices)
    {
        groups.push(createSigGroup(new Uint8Array(hashBuf, chi, config.group.numDeltaIndices)));
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
 * @throws {Errror} The delta values are invalid.
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

        if(sumArrayValues(groups[i].deltaIndices, 0, config.group.numDeltaIndices) !== sumZeroToN(config.group.maxDeltaIndex))
        {
            throw new Error("Invalid delta indices!");
        }
    
        if(sumArrayValues(groups[i].deltaValues, 0, config.group.numDeltaIndices) !== getLargestValue(groups[i].values))
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
    numDeltaIndices = -1;
    hasPermutationId = false;
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
