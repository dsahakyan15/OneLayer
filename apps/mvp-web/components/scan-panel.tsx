"use client";

import jsQR from "jsqr";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, publicApi, verify } from "../lib/api";
import { VerificationResult, type VerificationResponse, type VerifyEnvelope } from "./verification-result";

type Mode = "camera" | "image" | "manual";

const QR_PATTERN = /^https?:\/\/[^/]+\/c\/([0-9a-f]{32})\?h=([A-Za-z0-9_-]{43})$/;

/** The rendered result plus the envelope that produced it. */
interface Outcome {
  body: VerificationResponse;
  envelope: VerifyEnvelope;
}

/** A failure detected here, before a verifier answered: nothing is attributed upstream. */
function invalid(code: string): Outcome {
  return { body: { status: "INVALID", code, warnings: [] }, envelope: "local" };
}

/**
 * Scan, upload and manual entry share one verification path. Camera access is
 * progressive enhancement: refusing the permission never blocks the other two.
 */
export function ScanPanel({ initial }: { initial?: { certificateId: string; qrHash: string } }): ReactNode {
  const [mode, setMode] = useState<Mode>(initial === undefined ? "manual" : "manual");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [result, setResult] = useState<Outcome | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);

  useEffect(() => {
    if (initial === undefined) return;
    void checkCertificate(initial.certificateId, initial.qrHash);
    // The landing page verifies once on mount; further runs are user-driven.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => () => stopCamera(), []);

  function stopCamera(): void {
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
  }

  async function startCamera(): Promise<void> {
    setCameraError(null);
    setMode("camera");
    if (navigator.mediaDevices?.getUserMedia === undefined) {
      setCameraError("This browser exposes no camera. Use image upload or manual input.");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      streamRef.current = stream;
      if (videoRef.current !== null) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        void pollCamera();
      }
    } catch {
      setCameraError("Camera permission was denied. Image upload and manual input still work.");
    }
  }

  async function pollCamera(): Promise<void> {
    const video = videoRef.current;
    if (video === null || streamRef.current === null) return;
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    const context = canvas.getContext("2d");
    if (context !== null && video.videoWidth > 0) {
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const image = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(image.data, image.width, image.height);
      if (code !== null) {
        stopCamera();
        await submit(code.data);
        return;
      }
    }
    setTimeout(() => void pollCamera(), 250);
  }

  async function readImage(file: File): Promise<void> {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const context = canvas.getContext("2d");
    if (context === null) {
      setResult(invalid("QR_IMAGE_UNREADABLE"));
      return;
    }
    context.drawImage(bitmap, 0, 0);
    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(image.data, image.width, image.height);
    if (code === null) {
      setResult(invalid("QR_PAYLOAD_MISSING"));
      return;
    }
    await submit(code.data);
  }

  async function checkCertificate(certificateId: string, qrHash: string): Promise<void> {
    setBusy(true);
    setResult(null);
    try {
      // The QR hash is checked against the stored certificate hash before the
      // package is verified, so a swapped package fails immediately.
      const bundle = await publicApi(`/certificates/${certificateId}/package?h=${encodeURIComponent(qrHash)}`);
      const outcome = await verify(bundle.package_base64url);
      setResult({ body: outcome.body, envelope: outcome.protocol });
    } catch (error) {
      setResult(invalid(error instanceof ApiError ? error.code : "VERIFICATION_FAILED"));
    } finally {
      setBusy(false);
    }
  }

  async function submit(raw: string): Promise<void> {
    const value = raw.trim();
    const match = QR_PATTERN.exec(value);
    if (match !== null) {
      await checkCertificate(match[1], match[2]);
      return;
    }
    if (/^https?:\/\//.test(value)) {
      setResult(invalid("QR_URL_INVALID"));
      return;
    }
    if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length < 32) {
      setResult(invalid("CERTIFICATE_FORMAT_INVALID"));
      return;
    }
    setBusy(true);
    setResult(null);
    try {
      const outcome = await verify(value);
      setResult({ body: outcome.body, envelope: outcome.protocol });
    } catch (error) {
      setResult(invalid(error instanceof ApiError ? error.code : "VERIFICATION_FAILED"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="ol-card">
        <h2>Check a certificate</h2>
        <div className="ol-nav" role="group" aria-label="Input method">
          <button type="button" onClick={() => void startCamera()} data-testid="mode-camera" aria-pressed={mode === "camera"}>
            Camera
          </button>
          <button type="button" onClick={() => { stopCamera(); setMode("image"); }} data-testid="mode-image" aria-pressed={mode === "image"}>
            Image upload
          </button>
          <button type="button" onClick={() => { stopCamera(); setMode("manual"); }} data-testid="mode-manual" aria-pressed={mode === "manual"}>
            Manual input
          </button>
        </div>

        {mode === "camera" ? (
          <div>
            <video ref={videoRef} playsInline muted style={{ width: "100%", maxWidth: 420, borderRadius: 12 }} data-testid="camera-preview" />
            {cameraError !== null ? <p className="ol-error" data-testid="camera-error">{cameraError}</p> : null}
          </div>
        ) : null}

        {mode === "image" ? (
          <label className="ol-field">
            <span className="ol-label">QR image</span>
            <input
              type="file"
              accept="image/*"
              data-testid="qr-image-input"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file !== undefined) void readImage(file);
              }}
            />
          </label>
        ) : null}

        {mode === "manual" ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submit(input);
            }}
          >
            <label className="ol-field">
              <span className="ol-label">Certificate URL or package</span>
              <input
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="http://127.0.0.1:8091/c/…?h=… or a base64url package"
                data-testid="manual-input"
              />
            </label>
            <p>
              <button type="submit" data-variant="primary" disabled={busy} data-testid="manual-submit">
                {busy ? "Checking…" : "Check"}
              </button>
            </p>
          </form>
        ) : null}
      </section>

      {busy ? <p role="status" data-testid="checking">Checking the finalized Solana anchor…</p> : null}
      {result !== null ? <VerificationResult result={result.body} envelope={result.envelope} /> : null}
    </>
  );
}
