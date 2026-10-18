"""SignalMesh Loom Video Generator.

Generates a continuous, high-definition (1080p) video presentation
with voiceover narration, Loom-style presenter bubble, and scene subtitles.
Covers the entire user journey starting from the landing page through all
5 core dashboard pages, platform capability detection, and evaluation metrics.
Total duration: >= 2 minutes 30 seconds (150+ seconds).
"""

from pathlib import Path
import subprocess
import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

# Workspace paths
WORKSPACE_DIR = Path(__file__).resolve().parent.parent.parent
RENDER_DIR = WORKSPACE_DIR / "backend" / "scratch" / "loom_render"
RENDER_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_MP4 = WORKSPACE_DIR / "signalmesh_loom_presentation_walkthrough.mp4"

# 12 Scenes covering Landing Page -> All 5 Dashboard Views in Sequence
SCENES = [
    {
        "id": "scene_01",
        "title": "SignalMesh — Privacy-Preserving AML Collaboration",
        "section": "01/12 • LANDING PAGE INTRODUCTION",
        "image_path": "/Users/gyanprakash09/.gemini/antigravity-ide/brain/c083dc2c-6bc2-4da9-a4f4-17e9b90c9f5e/landing_hero_1792311516783.png",
        "narration": "Welcome to SignalMesh, a privacy-preserving financial intelligence platform engineered for the IBM Z Datathon. Modern money laundering cartels systematically exploit inter-bank visibility gaps by structuring smurfing transactions across separate financial institutions.",
        "min_duration": 13.0,
    },
    {
        "id": "scene_02",
        "title": "The Privacy Dilemma: Regulatory Data-Sharing Barriers",
        "section": "02/12 • REGULATORY DATA SILOS",
        "image_path": "/Users/gyanprakash09/.gemini/antigravity-ide/brain/c083dc2c-6bc2-4da9-a4f4-17e9b90c9f5e/landing_workflow_1792311550141.png",
        "narration": "Under GDPR, CCPA, and strict bank secrecy laws, institutions are legally prohibited from pooling raw customer transaction records. SignalMesh resolves this fundamental tension using Private Set Intersection, allowing banks to discover overlapping suspicious entities without centralizing customer data.",
        "min_duration": 13.5,
    },
    {
        "id": "scene_03",
        "title": "Cryptographic Trust Boundaries & Zero Data Leakage",
        "section": "03/12 • SYSTEM BOUNDARIES & ARCHITECTURE",
        "image_path": "/Users/gyanprakash09/.gemini/antigravity-ide/brain/c083dc2c-6bc2-4da9-a4f4-17e9b90c9f5e/landing_privacy_1792311585341.png",
        "narration": "Raw transaction records remain strictly within each bank's local agent memory. Customer entities are converted to canonical cryptographic tokens, verified over elliptic curves, and recorded in a verifiable audit ledger. Now, let us enter the live operational dashboard.",
        "min_duration": 13.0,
    },
    {
        "id": "scene_04",
        "title": "Operational Overview Dashboard & Live Telemetry",
        "section": "04/12 • OVERVIEW DASHBOARD",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/01_overview_dashboard.png",
        "narration": "Entering the live SignalMesh dashboard. We monitor three autonomous simulated participants: Bank A Retail, Bank B Corporate, and Bank C Correspondent. The system tracks 55 local transactions, 68 graph accounts, and four flagged suspicious leads backed by an active cryptographic hash chain.",
        "min_duration": 14.0,
    },
    {
        "id": "scene_05",
        "title": "Local Data Ingestion & Schema Conformance Guard",
        "section": "05/12 • DATA VALIDATION & PRIVACY GUARD",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/02_schema_validation.png",
        "narration": "Navigating to the Investigations page, we inspect Bank A's isolated transaction feed. The system performs automated schema validation, verifying non-negative amounts, ISO UTC timestamps, and asserting zero ground-truth label leakage into operational workflows.",
        "min_duration": 13.0,
    },
    {
        "id": "scene_06",
        "title": "Local Rule-Based Detection: Smurfing & Fan-In",
        "section": "06/12 • LOCAL DETECTION ENGINE",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/03_flagged_smurfing_leads.png",
        "narration": "Bank A executes its local detection engine. Structuring smurfing, rapid pass-through, fan-in/fan-out, and high-value conduit rules evaluate graph features. Account ACC_A_1001 is flagged with an elevated 0.85 local risk score, computed entirely within local memory.",
        "min_duration": 13.5,
    },
    {
        "id": "scene_07",
        "title": "Investigation Dossier & Explainable Compliance Evidence",
        "section": "07/12 • EXPLAINABLE EVIDENCE DOSSIER",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/04_evidence_dossier.png",
        "narration": "Opening the investigation dossier for account ACC_A_1001, compliance analysts inspect exact explainable evidence: two cash deposits totaling $19,550 structured just below the $10,000 CTR threshold, a 0.997 turnover ratio, and high fan-in aggregation across counterparties.",
        "min_duration": 14.0,
    },
    {
        "id": "scene_08",
        "title": "Transaction Network: Directed Multigraph Visualization",
        "section": "08/12 • TRANSACTION NETWORK TOPOLOGY",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/05_transaction_network.png",
        "narration": "The Transaction Network visualizes the directed transaction multigraph. Red nodes indicate flagged suspicious accounts, cyan nodes represent local non-suspicious accounts, and slate nodes represent external counterparties. Selecting nodes populates the entity inspector with degree and flow metrics.",
        "min_duration": 14.0,
    },
    {
        "id": "scene_09",
        "title": "Bank Collaboration: IBM LinuxONE (s390x) Capability Guard",
        "section": "09/12 • LINUXONE PLATFORM CAPABILITY",
        "image_path": "/Users/gyanprakash09/.gemini/antigravity-ide/brain/c083dc2c-6bc2-4da9-a4f4-17e9b90c9f5e/bank_collaboration_page_1792338534451.png",
        "narration": "On the Bank Collaboration page, we examine the six-stage privacy pipeline. SignalMesh features real-time platform capability detection. On IBM LinuxONE s390x, OpenMined PSI native build is blocked due to BoringSSL assembly constraints. We maintain scientific honesty by disabling execution rather than fabricating math.",
        "min_duration": 14.5,
    },
    {
        "id": "scene_10",
        "title": "Cryptographic PSI Collaboration (Mac Development Host)",
        "section": "10/12 • REAL PSI CRYPTOGRAPHIC MATCHING",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/06_cross_bank_psi_execution.png",
        "narration": "On our Mac host where native PSI is compiled, we execute genuine ECDH-OPRF Diffie-Hellman cryptographic matching. Asymmetric revelation ensures only the recipient client learns matching indices, revealing eight cross-bank overlaps and 1,284 serialized protocol bytes across three pairwise sessions.",
        "min_duration": 14.5,
    },
    {
        "id": "scene_11",
        "title": "Verifiable Privacy Leakage Ledger: SHA-256 Hash Chain",
        "section": "11/12 • AUDIT LEDGER & HASH CHAIN",
        "image_path": "/Users/gyanprakash09/.gemini/antigravity-ide/brain/c083dc2c-6bc2-4da9-a4f4-17e9b90c9f5e/audit_ledger_page_1792338570967.png",
        "narration": "In the Audit and Evaluation section, all observable protocol telemetry is logged to an immutable SQLite ledger. Running the on-demand SHA-256 verification confirms the cryptographic hash chain is completely unbroken with zero record tampering, reordering, or internal deletion.",
        "min_duration": 13.5,
    },
    {
        "id": "scene_12",
        "title": "Scientific Ground-Truth Evaluation: Zero False Alarms",
        "section": "12/12 • GROUND-TRUTH CONFUSION MATRIX",
        "image_path": "/Users/gyanprakash09/Developer/Zdatathon/demo_showcase/07_audit_hash_chain_and_evaluation.png",
        "narration": "Finally, we evaluate performance against isolated ground-truth labels. The confusion matrix yields 100.0% Precision with zero false alarms, 42.9% Recall, and a 60.0% F1 harmonic score. SignalMesh proves that privacy-preserving collaborative AML is mathematically sound, audit-verifiable, and ready for enterprise adoption.",
        "min_duration": 15.5,
    },
]


def generate_audio(text: str, aiff_path: Path) -> float:
    """Generates natural voiceover using macOS say -v Daniel and returns duration in seconds."""
    cmd = ["say", "-v", "Daniel", "-r", "165", "-o", str(aiff_path), text]
    subprocess.run(cmd, check=True)
    
    # Measure duration with ffprobe
    probe_cmd = [
        "/opt/homebrew/bin/ffprobe",
        "-i", str(aiff_path),
        "-show_entries", "format=duration",
        "-v", "quiet",
        "-of", "csv=p=0",
    ]
    res = subprocess.run(probe_cmd, capture_output=True, text=True, check=True)
    dur = float(res.stdout.strip())
    return dur


def compose_frame(scene: dict, output_png: Path):
    """Composes a 1920x1080 frame with screenshot, presenter avatar bubble, and lower-third narrative."""
    # 1. Base 1920x1080 canvas
    canvas = Image.new("RGB", (1920, 1080), "#060813")
    draw = ImageDraw.Draw(canvas)

    # 2. Load screenshot and scale to fit upper workspace (1920x960)
    img_path = Path(scene["image_path"])
    if img_path.exists():
        src_img = Image.open(img_path).convert("RGB")
        # Crop or scale nicely
        target_w, target_h = 1920, 940
        ratio = max(target_w / src_img.width, target_h / src_img.height)
        new_size = (int(src_img.width * ratio), int(src_img.height * ratio))
        resized = src_img.resize(new_size, Image.Resampling.LANCZOS)
        
        # Crop top-aligned
        cropped = resized.crop((0, 0, target_w, target_h))
        canvas.paste(cropped, (0, 0))

    # 3. Add subtle dark gradient overlay between screenshot and lower-third
    for y in range(900, 960):
        alpha = int((y - 900) / 60 * 255)
        draw.line([(0, y), (1920, y)], fill=(6, 8, 19, alpha))

    # 4. Draw Lower-Third Presentation Banner (Y: 940 to 1080)
    draw.rectangle([(0, 940), (1920, 1080)], fill="#0A0E1F")
    # Top cyan accent line
    draw.line([(0, 940), (1920, 940)], fill="#06B6D4", width=3)

    # Text Fonts
    try:
        font_section = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 15)
        font_title = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 22)
        font_sub = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 16)
        font_badge = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 12)
    except Exception:
        font_section = ImageFont.load_default()
        font_title = ImageFont.load_default()
        font_sub = ImageFont.load_default()
        font_badge = ImageFont.load_default()

    # Section / Chapter tag
    draw.text((210, 952), scene["section"], fill="#38BDF8", font=font_section)
    # Title
    draw.text((210, 975), scene["title"], fill="#FFFFFF", font=font_title)
    
    # Subtitle / Spoken narrative (truncate or wrap to 2 lines)
    words = scene["narration"].split()
    line1 = " ".join(words[:18])
    line2 = " ".join(words[18:38]) + ("..." if len(words) > 38 else "")
    draw.text((210, 1012), line1, fill="#CBD5E1", font=font_sub)
    draw.text((210, 1038), line2, fill="#94A3B8", font=font_sub)

    # 5. Loom Presenter Circle Bubble (Left side: X: 35, Y: 945, radius 60)
    cx, cy, r = 110, 1010, 52
    draw.ellipse([(cx - r - 4, cy - r - 4), (cx + r + 4, cy + r + 4)], fill="#06B6D4")
    draw.ellipse([(cx - r, cy - r), (cx + r, cy + r)], fill="#0F172A")
    
    # Draw avatar initials or graphic
    draw.text((cx - 24, cy - 14), "GP", fill="#FFFFFF", font=font_title)
    
    # Green live recording indicator dot
    draw.ellipse([(cx + 32, cy - 38), (cx + 46, cy - 24)], fill="#10B981")
    draw.ellipse([(cx + 35, cy - 35), (cx + 43, cy - 27)], fill="#FFFFFF")

    # Presenter tag below avatar
    draw.rectangle([(25, 1058), (195, 1076)], fill="#141E34")
    draw.text((32, 1061), "Gyan Prakash • Architect", fill="#94A3B8", font=font_badge)

    canvas.save(output_png, quality=95)


def build_scene_segment(scene: dict, index: int) -> tuple[Path, float]:
    """Generates audio, frame, and renders an individual MP4 segment."""
    base_name = f"seg_{index:02d}_{scene['id']}"
    audio_path = RENDER_DIR / f"{base_name}.aiff"
    frame_path = RENDER_DIR / f"{base_name}.png"
    segment_mp4 = RENDER_DIR / f"{base_name}.mp4"

    print(f"[{index + 1}/12] Generating audio for {scene['title']}...")
    raw_dur = generate_audio(scene["narration"], audio_path)
    
    # Pad duration slightly for natural pauses
    final_dur = max(raw_dur + 1.8, scene["min_duration"])
    print(f"     Spoken duration: {raw_dur:.2f}s -> Video segment: {final_dur:.2f}s")

    print(f"     Composing 1080p frame...")
    compose_frame(scene, frame_path)

    print(f"     Rendering MP4 segment with ffmpeg...")
    # Render video segment matching audio length
    cmd = [
        "/opt/homebrew/bin/ffmpeg", "-y",
        "-loop", "1", "-t", f"{final_dur:.2f}",
        "-i", str(frame_path),
        "-i", str(audio_path),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", "30",
        "-c:a", "aac", "-b:a", "192k",
        "-shortest",
        str(segment_mp4)
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return segment_mp4, final_dur


def main():
    print("=================================================================")
    print("SignalMesh Loom Presentation Video Generator (>= 2:30s)")
    print("=================================================================")

    segment_paths = []
    total_time = 0.0

    for idx, scene in enumerate(SCENES):
        seg_path, dur = build_scene_segment(scene, idx)
        segment_paths.append(seg_path)
        total_time += dur

    print("-----------------------------------------------------------------")
    print(f"All 12 segments rendered! Total combined duration: {total_time:.2f} seconds ({total_time/60:.2f} minutes).")
    print("Concatenating into final submission MP4...")

    # Write concat list
    concat_file = RENDER_DIR / "concat_list.txt"
    with open(concat_file, "w") as f:
        for p in segment_paths:
            f.write(f"file '{p.resolve()}'\n")

    # Final concatenation
    concat_cmd = [
        "/opt/homebrew/bin/ffmpeg", "-y",
        "-f", "concat", "-safe", "0",
        "-i", str(concat_file),
        "-c", "copy",
        str(OUTPUT_MP4)
    ]
    subprocess.run(concat_cmd, check=True)

    # Verify final duration with ffprobe
    probe_cmd = [
        "/opt/homebrew/bin/ffprobe",
        "-i", str(OUTPUT_MP4),
        "-show_entries", "format=duration",
        "-v", "quiet",
        "-of", "csv=p=0",
    ]
    res = subprocess.run(probe_cmd, capture_output=True, text=True, check=True)
    actual_dur = float(res.stdout.strip())

    file_size_mb = OUTPUT_MP4.stat().st_size / (1024 * 1024)
    minutes = int(actual_dur // 60)
    seconds = int(actual_dur % 60)

    print("=================================================================")
    print(f"SUCCESS: Rendered Final Loom Presentation Video!")
    print(f"File Path: {OUTPUT_MP4}")
    print(f"File Size: {file_size_mb:.2f} MB")
    print(f"Duration:  {minutes}:{seconds:02d} ({actual_dur:.2f} seconds)")
    print(f"Resolution: 1920x1080 (Full HD, 30 fps, H.264/AAC)")
    print("=================================================================")

    if actual_dur < 150.0:
        raise ValueError(f"Duration {actual_dur}s is below 150s minimum!")


if __name__ == "__main__":
    main()
