"""
Generate Untangled Architecture Diagram for Virodh AI (Threat Guard)
Outputs a pristine 4K (300 DPI) diagram without tangled crossing arrows,
featuring the unified untangled server architecture (virodh.server:app + Node BFF + React console).
"""

import os
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch

def create_untangled_architecture_diagram(output_path: str):
    # 16:9 widescreen canvas, 300 DPI (approx 7800 x 4300)
    fig, ax = plt.subplots(figsize=(26, 14.5), dpi=300)

    # Color Palette - Modern Cyber Dark Mode
    bg_color = "#0B0F19"         # Deep obsidian navy
    canvas_border = "#1E293B"    # Slate border
    card_bg = "#111827"          # Dark gray-blue card
    card_border = "#334155"      # Medium slate border
    subcard_bg = "#1F2937"       # Slightly lighter inner box
    subcard_border = "#374151"

    text_white = "#F8FAFC"
    text_muted = "#94A3B8"
    text_dim = "#64748B"

    # Accents
    accent_cyan = "#06B6D4"      # Cyan - Ingress & Client
    accent_blue = "#3B82F6"      # Blue - Untangled Server & Gateway
    accent_purple = "#A855F7"    # Purple - Multi-Modal Extraction
    accent_amber = "#F59E0B"     # Amber - Parallel Threat Detectors
    accent_rose = "#F43F5E"      # Rose - Adversarial
    accent_emerald = "#10B981"   # Emerald - Policy Gate & Safe ALLOW
    accent_red = "#EF4444"       # Red - Refusal & BLOCK
    accent_indigo = "#6366F1"    # Indigo - Target VLMs & Output Guard

    fig.patch.set_facecolor(bg_color)
    ax.set_facecolor(bg_color)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Helper: Main Column Card
    def draw_card(x, y, w, h, title="", subtitle="", color=card_border, fill=card_bg, radius=1.2, lw=1.5):
        box = FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad=0.2,rounding_size={radius}",
            facecolor=fill, edgecolor=color, linewidth=lw, zorder=2
        )
        ax.add_patch(box)
        if title:
            ax.text(x + 1.2, y + h - 2.4, title, fontsize=11.5, fontweight="bold", color=text_white, zorder=5)
        if subtitle:
            ax.text(x + 1.2, y + h - 4.4, subtitle, fontsize=8.2, color=text_muted, zorder=5)
        return box

    # Helper: Tag Badge
    def draw_badge(x, y, text, color=accent_cyan, text_color="#FFFFFF", font_size=7.5, pad_w=0.55):
        w = len(text) * pad_w + 1.2
        box = FancyBboxPatch(
            (x, y), w, 1.9,
            boxstyle="round,pad=0.15,rounding_size=0.5",
            facecolor=color, edgecolor="none", zorder=6
        )
        ax.add_patch(box)
        ax.text(x + w / 2, y + 0.55, text, fontsize=font_size, fontweight="bold",
                color=text_color, ha="center", va="center", zorder=7)

    # Helper: Subcard Component Box
    def draw_item_box(x, y, w, h, title, desc, tag="", tag_color=accent_cyan, border=subcard_border, bg=subcard_bg):
        box = FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.15,rounding_size=0.7",
            facecolor=bg, edgecolor=border, linewidth=1.1, zorder=3
        )
        ax.add_patch(box)
        ax.text(x + 0.9, y + h - 1.8, title, fontsize=9.2, fontweight="bold", color=text_white, zorder=5)
        ax.text(x + 0.9, y + h - 3.4, desc, fontsize=7.8, color=text_muted, zorder=5, linespacing=1.25)
        if tag:
            draw_badge(x + w - len(tag) * 0.50 - 1.2, y + h - 2.1, tag, color=tag_color, font_size=6.8)

    # Helper: Directional Arrow
    def draw_arrow(x1, y1, x2, y2, color=text_muted, lw=1.8, style="-|>", rad=0.0, linestyle="-"):
        arrow = patches.FancyArrowPatch(
            (x1, y1), (x2, y2),
            connectionstyle=f"arc3,rad={rad}",
            arrowstyle=style,
            mutation_scale=14,
            linewidth=lw,
            linestyle=linestyle,
            color=color,
            zorder=10
        )
        ax.add_patch(arrow)

    # ==========================================
    # HEADER SECTION
    # ==========================================
    draw_badge(3.0, 94.0, "VIRODH AI PRODUCTION ARCHITECTURE", color=accent_emerald, text_color="#000000", font_size=8.5)
    ax.text(28.0, 95.1, "UNTANGLED SERVER & MULTIMODAL FIREWALL ARCHITECTURE", fontsize=19, fontweight="heavy", color=text_white, zorder=5)
    ax.text(3.0, 91.5, "End-to-End Multimodal Defense: Ingress Interfaces • Untangled Server Gateway • Multi-Modal Extraction • Parallel Detectors • Calibrated Policy Gate • Protected VLMs",
            fontsize=9.8, color=text_muted, zorder=5)

    ax.plot([3.0, 97.0], [90.0, 90.0], color=canvas_border, lw=1.5, zorder=1)

    # ==========================================
    # COLUMN 1: INGRESS & CLIENT INTERFACES (X: 3.0 -> 19.5, W: 16.5)
    # ==========================================
    draw_card(
        3.0, 11.5, 16.5, 76.5,
        title="1. INGRESS & INTERFACES",
        subtitle="Client apps, web console & input ingestion",
        color=accent_cyan, lw=1.8
    )

    draw_item_box(
        4.0, 71.5, 14.5, 11.0,
        title="React Management Console",
        desc="Interactive playground, real-time requests\ntelemetry, policy editor, and key provisioning.",
        tag="web/ (Port 5173/3000)", tag_color="#0284C7"
    )

    draw_item_box(
        4.0, 58.5, 14.5, 11.0,
        title="OpenAI-Compatible SDKs",
        desc="Drop-in proxy for standard OpenAI client,\nLangChain, LlamaIndex, & enterprise bots.",
        tag="/v1/chat/completions", tag_color="#0284C7"
    )

    draw_item_box(
        4.0, 45.5, 14.5, 11.0,
        title="Direct Inspection REST API",
        desc="High-throughput multimodal guard scan\nand security red-teaming lab endpoints.",
        tag="/v1/guard/scan", tag_color="#0284C7"
    )

    draw_item_box(
        4.0, 32.5, 14.5, 11.0,
        title="Benchmark & CLI Pipelines",
        desc="Automated batch test case execution,\nevaluation suites, and audit runners.",
        tag="run_pipeline.py", tag_color="#475569"
    )

    draw_item_box(
        4.0, 14.0, 14.5, 16.5,
        title="Ingress Validator & Sanitizer",
        desc="• Safe decompression & format verification\n• Image dimension & resolution clamping\n• EXIF metadata stripping & RGBA audit\n• Payload length & MIME envelope integrity",
        tag="guard/ingress.py", tag_color=accent_cyan
    )

    # ==========================================
    # COLUMN 2: UNTANGLED SERVER & GATEWAY (X: 21.5 -> 39.5, W: 18.0)
    # ==========================================
    draw_card(
        21.5, 11.5, 18.0, 76.5,
        title="2. UNTANGLED SERVER & GATEWAY",
        subtitle="Unified FastAPI engine, Node BFF & storage",
        color=accent_blue, lw=1.8
    )

    draw_item_box(
        22.5, 71.5, 16.0, 11.0,
        title="Unified FastAPI Gateway Server",
        desc="Core server hosting /v1 firewall, /admin/api,\nresearch lab /api, and OpenAPI documentation.",
        tag="virodh.server:app (:8000)", tag_color=accent_blue
    )

    draw_item_box(
        22.5, 58.5, 16.0, 11.0,
        title="Node.js Dashboard Backend & BFF",
        desc="Express-based session auth, role isolation,\nCSRF defense & proxy bridge to Python engine.",
        tag="server/src/index.js (:3000)", tag_color=accent_blue
    )

    draw_item_box(
        22.5, 45.5, 16.0, 11.0,
        title="Security Gateway Controller",
        desc="Token-bucket rate limiter (RPM/RPD), SSE\nstreaming passthrough, model spec routing.",
        tag="virodh/gateway.py", tag_color=accent_blue
    )

    draw_item_box(
        22.5, 32.5, 16.0, 11.0,
        title="Audit & Telemetry Persistence",
        desc="Zero-dependency SQLite WAL database for\nuser accounts, hashed keys, and request logs.",
        tag="data/virodh/ (WAL SQLite)", tag_color="#2563EB"
    )

    draw_item_box(
        22.5, 14.0, 16.0, 16.5,
        title="Inspector Orchestrator",
        desc="• Asynchronous thread-pool execution\n• Subprocess timeout guard (fail-safe)\n• Fast-path clean cache bypass\n• Prepares normalized multimodal context",
        tag="virodh/inspector.py", tag_color=accent_blue
    )

    # ==========================================
    # COLUMN 3: MULTI-MODAL EXTRACTION (X: 41.5 -> 58.5, W: 17.0)
    # ==========================================
    draw_card(
        41.5, 11.5, 17.0, 76.5,
        title="3. MULTI-MODAL EXTRACTION LAYER",
        subtitle="Recovers hidden, encoded, rotated visual text",
        color=accent_purple, lw=1.8
    )

    draw_item_box(
        42.5, 71.5, 15.0, 11.0,
        title="Full-Resolution QR / Barcode Decoder",
        desc="Extracts payloads from native-res barcodes\nbefore downstream model downsampling.",
        tag="guard/extract/qr.py", tag_color=accent_purple
    )

    draw_item_box(
        42.5, 58.5, 15.0, 11.0,
        title="Multi-View OCR Pipeline",
        desc="Extracts text across geometric views:\n• Standard • Inverted • Mirrored • Rotated",
        tag="guard/extract/ocr.py", tag_color=accent_purple
    )

    draw_item_box(
        42.5, 45.5, 15.0, 11.0,
        title="Contrast & Readability Engine",
        desc="Per-line ink contrast against background;\ndetects faint / invisible canary injections.",
        tag="text_quality.py", tag_color=accent_purple
    )

    draw_item_box(
        42.5, 32.5, 15.0, 11.0,
        title="Cipher & Steganography Decoders",
        desc="De-obfuscates hidden text payloads:\n• Base64 • Rot13 • Word-subst • Leetspeak",
        tag="decoders.py", tag_color=accent_purple
    )

    draw_item_box(
        42.5, 14.0, 15.0, 16.5,
        title="AnalysisContext Assembly",
        desc="• Untrusted visual text tokens with bounds\n• Cross-modal composite string builder\n• View metadata and decoding audit trail\n• Normalized feature representations",
        tag="extract/pipeline.py", tag_color="#7E22CE"
    )

    # ==========================================
    # COLUMN 4: PARALLEL DETECTION SUITE (X: 60.5 -> 78.5, W: 18.0)
    # ==========================================
    draw_card(
        60.5, 11.5, 18.0, 76.5,
        title="4. PARALLEL DETECTION ENGINES",
        subtitle="Evaluates semantic, cross-modal & pixel threats",
        color=accent_amber, lw=1.8
    )

    draw_item_box(
        61.5, 71.5, 16.0, 11.0,
        title="Prompt Injection Detector",
        desc="Detects visual commands targeting VLM logic\n(e.g., 'Ignore previous guidelines', hijacks).",
        tag="detectors/injection.py", tag_color=accent_amber
    )

    draw_item_box(
        61.5, 58.5, 16.0, 11.0,
        title="Direct Harm Detector",
        desc="Screens text segments for safety hazards:\nmalware, cyber attacks, exploits, violence.",
        tag="detectors/harm.py", tag_color=accent_amber
    )

    draw_item_box(
        61.5, 45.5, 16.0, 11.0,
        title="Cross-Modal Composite Detector",
        desc="Detects split attacks: prompt and image text\nare benign individually but hazardous together.",
        tag="detectors/composite.py", tag_color=accent_amber
    )

    draw_item_box(
        61.5, 32.5, 16.0, 11.0,
        title="Obfuscation & Distortion Detector",
        desc="Scores risk for deliberate visual disguises:\ncharacter flips, warped text, cipher tokens.",
        tag="detectors/obfuscation.py", tag_color=accent_amber
    )

    draw_item_box(
        61.5, 14.0, 16.0, 16.5,
        title="Adversarial Perturbation Engine",
        desc="• Sub-pixel noise classifier (KMP-safe Windows)\n• Gradient perturbation detection (FGSM/PGD)\n• Cross-channel feature correlation analysis\n• High-frequency spatial noise audit",
        tag="guard/adversarial/", tag_color=accent_rose
    )

    # ==========================================
    # COLUMN 5: POLICY GATE & UPSTREAM VLMs (X: 80.5 -> 97.5, W: 17.0)
    # ==========================================
    draw_card(
        80.5, 11.5, 17.0, 76.5,
        title="5. POLICY GATE & UPSTREAM VLMS",
        subtitle="Arbitration, protected execution & output guard",
        color=accent_emerald, lw=1.8
    )

    draw_item_box(
        81.5, 73.5, 15.0, 9.5,
        title="Risk Fusion Engine",
        desc="Weighted multi-detector scoring with\nfloor overrides for severe single violations.",
        tag="guard/fusion.py", tag_color=accent_emerald
    )

    draw_item_box(
        81.5, 59.5, 15.0, 12.0,
        title="Policy Arbitrator Gate",
        desc="Evaluates risk against threshold profiles:\n• ALLOW: Safe to proceed to VLM\n• REVIEW: Operator hold / queue\n• BLOCK: Immediate rejection envelope",
        tag="guard/policy.py", tag_color=accent_emerald
    )

    draw_item_box(
        81.5, 43.5, 15.0, 13.5,
        title="Protected Upstream VLMs",
        desc="• Google Gemini 1.5 Pro / Flash\n• Groq Qwen2-VL-72B\n• OpenAI GPT-4o\nProtected by pre-execution firewall.",
        tag="Upstream LLM/VLM", tag_color=accent_indigo
    )

    draw_item_box(
        81.5, 29.0, 15.0, 12.5,
        title="Output Guard Interceptor",
        desc="Scans post-generation model response for\nsafety leaks, canary words, or reflected\nhazardous payloads.",
        tag="output_guard.py", tag_color=accent_indigo
    )

    draw_item_box(
        81.5, 14.0, 15.0, 13.0,
        title="Refusal & Envelope Dispatcher",
        desc="Returns clean rejection envelope or refusal\nmessage directly to client (HTTP 200/400)\nwithout calling upstream models.",
        tag="Refusal Dispatcher", tag_color=accent_red
    )

    # ==========================================
    # UNTANGLED PIPELINE ARROWS (LINEAR & PERIMETER ROUTED)
    # ==========================================
    # 1. Ingress -> Gateway (Linear horizontal)
    draw_arrow(19.5, 77.0, 21.5, 77.0, color=accent_cyan, lw=2.2)
    draw_arrow(19.5, 22.0, 21.5, 22.0, color=accent_cyan, lw=2.2)
    ax.text(20.5, 78.2, "API Req", fontsize=7.2, color=accent_cyan, ha="center")
    ax.text(20.5, 23.2, "Sanitized", fontsize=7.2, color=accent_cyan, ha="center")

    # 2. Gateway -> Extraction Layer (Linear horizontal)
    draw_arrow(39.5, 22.0, 41.5, 22.0, color=accent_blue, lw=2.2)
    ax.text(40.5, 23.2, "Context", fontsize=7.2, color=accent_blue, ha="center")

    # 3. Extraction -> Parallel Detectors (Linear horizontal)
    draw_arrow(58.5, 22.0, 60.5, 22.0, color=accent_purple, lw=2.2)
    ax.text(59.5, 23.2, "Tokens & Views", fontsize=7.2, color=accent_purple, ha="center")

    # 4. Parallel Detectors -> Fusion Engine (Clean horizontal bus)
    draw_arrow(78.5, 77.0, 80.5, 77.0, color=accent_amber, lw=2.2)
    ax.text(79.5, 78.2, "Scores", fontsize=7.2, color=accent_amber, ha="center")

    # 5. Fusion -> Policy Gate (Clean downward inside Col 5)
    draw_arrow(89.0, 73.5, 89.0, 71.5, color=accent_emerald, lw=2.2)

    # 6. Policy Decision Branches (Inside Col 5, ZERO CROSSING):
    # Branch A: ALLOW -> Proceed down to Target VLMs
    draw_arrow(86.0, 59.5, 86.0, 57.0, color=accent_emerald, lw=2.5)
    draw_badge(82.5, 57.5, "ALLOW (Safe)", color=accent_emerald, text_color="#000000", font_size=7.2)

    # Target VLMs -> Output Guard
    draw_arrow(86.0, 43.5, 86.0, 41.5, color=accent_indigo, lw=2.2)

    # Output Guard -> Completed Safe Response (Out to bottom highway)
    draw_arrow(86.0, 29.0, 86.0, 11.5, color=accent_emerald, lw=2.2, linestyle="-")

    # Branch B: BLOCK -> Downward directly to Refusal Dispatcher
    draw_arrow(92.0, 59.5, 92.0, 27.0, color=accent_red, lw=2.5, linestyle="--")
    draw_badge(90.2, 42.0, "BLOCK", color=accent_red, text_color="#FFFFFF", font_size=7.2)

    # Refusal Dispatcher -> Out to bottom highway
    draw_arrow(92.0, 14.0, 92.0, 11.5, color=accent_red, lw=2.2, linestyle="-")

    # ==========================================
    # CLEAN BOTTOM RETURN HIGHWAY (UNTANGLED PERIMETER BUS)
    # ==========================================
    # Draws the return data path running underneath the cards along Y=7.0 back to Client Ingress
    ax.plot([86.0, 86.0], [11.5, 7.0], color=accent_emerald, lw=2.0)
    ax.plot([92.0, 92.0], [11.5, 7.0], color=accent_red, lw=2.0)
    ax.plot([11.0, 92.0], [7.0, 7.0], color=canvas_border, lw=2.0, linestyle="--")
    draw_arrow(11.0, 7.0, 11.0, 11.5, color=text_white, lw=2.2)
    draw_badge(46.0, 6.0, "RETURN DATA HIGHWAY: Verified Safe Output OR Refusal Envelope -> Client Application", color="#1E293B", text_color="#38BDF8", font_size=8.0)

    # Save to high-res PNG
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, facecolor=bg_color, edgecolor="none", bbox_inches="tight")
    plt.close()
    print(f"Untangled architecture diagram successfully saved to {output_path}")

if __name__ == "__main__":
    downloads_dir = Path(os.environ["USERPROFILE"]) / "Downloads"
    target_file = downloads_dir / "threat_guard_full_architecture.png"
    create_untangled_architecture_diagram(str(target_file))

    # Also save to docs/assets
    docs_file = Path("docs") / "assets" / "threat_guard_full_architecture.png"
    create_untangled_architecture_diagram(str(docs_file))
