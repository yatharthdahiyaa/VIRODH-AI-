# Limitations (read before quoting any number)

## Evaluation
- **Small samples**: ~50 test cases per attack, 61 benign test cases (36 hard negatives). Differences of
  a few percentage points are not meaningful.
- **One benchmark target model**: Gemini 3.5 Flash-Lite (free tier). Qwen 3.8 on Groq hit its
  200k-tokens/day cap on day 1 and is used only for the live demo. Results may not transfer to other models.
- **Free-tier rate limits** dropped some unguarded responses; coverage is reported per attack (n).
- **Harmful-attack success** needs the LLM judge. Where judge results are missing, the report shows a
  *non-refusal proxy* and labels it as such — that proxy overstates harm.
- **Synthetic attacks**: the QR-code and canary attacks are ours, not published methods. Canary test
  cases use held-out wording (pool B), but they come from the same generators as the validation cases.
- **Benchmark attacks** (FigStep, MML) were generated with the upstream code; one upstream bug was fixed
  (`mml_base64`). MML's word-replacement prompt describes its dictionary in the reverse direction to
  how it is built; we left the attack as published.
- **HADES was not evaluated yet.** The paper's PixArt-generated image (needs ~10 GB of GPU memory) and its
  adversarial noise against the target's own vision encoder (impossible for hosted models) cannot be
  reproduced here. The upstream implementation has neither the noise step nor a hard PixArt dependency:
  with `creat_image: false` it uses the dataset image + keyword typography, which is feasible
  (needs an auxiliary LLM and the `diffusers` package for its import).

## Adversarial image engine (guard/adversarial)
- **After the improvement loop** (eval/adversarial/loop.py + iter4_noise_robust.py; 1,500 adversarial +
  1,200 benign images, +900 noisy benign in round 4; fitted on train, threshold on val, reported on test):
  the live model (round 4) detects 98.6% of FGSM/PGD test images at 0.5% false positives (baseline 9%).
- **Stress test on unseen conditions** (generalization.py, 100 test sources): round 4 cut false alarms on
  new noise types (shot 48→10%, uniform 41→6%, grey-only 100→41%, sigma 0.01 74→50%) **but lost
  sensitivity to very weak unseen attacks** (PGD 2/255 88→27%, FGSM 1/255 17→3%). Perturbations of 1–2
  grey levels look like light sensor noise to these features. Light noise is still flagged too often
  (sigma 0.01: 50%). Round 3 is kept as `config/adversarial_model_iter3.joblib` for rollback. We did not
  tune further on the stress-test results. The paragraphs below describe the original rule-based engine.
- **Weak detection on our data (rule-based baseline).** On the test split (100 source photos), FGSM/PGD changed the local
  ResNet18 prediction in 100% of cases, but the default (strict) threshold flagged only **9%** of them
  (2% false positives on clean, 3% on benign corruptions). A sensitive threshold flags 16% but also
  46% of benign Gaussian-noise images.
- **Why:** lightweight statistics detect noise-like perturbation but cannot separate it from benign
  Gaussian noise, and clean seed images vary widely (some are noisier than FGSM 8/255). Prediction
  consistency (Feature-Squeezing idea) fails because the seed images are AI-generated scenes outside
  ImageNet: ResNet18 is unsure (median clean confidence ~25–30%) and benign JPEG/resize already change
  its prediction ~55% of the time.
- **Calibration domain:** calibrated on natural photos only. Documents, screenshots and text cards
  (≥85% flat pixels) are reported as *not analysed* (gate 60%); without the gate ~50% of our hard
  negatives were flagged. With both engines, benign test false positives are 2/61 (multimodal alone 1/61).
- Results are against a **local ResNet18**, not the hosted VLM; the engine never names the attack
  family; adaptive attackers can bypass such detectors (Carlini & Wagner, 2017).
- Better next steps: evaluate on in-distribution natural photos (e.g. an ImageNet subset), add a
  learned detector, or attack/defend the VLM's own vision encoder (needs a GPU).

## Guard
- **Hosted classifiers**: harm and injection judgements depend on gpt-oss / Gemini / Prompt Guard via
  APIs. If they fail, the guard **fails safe** (REVIEW), which costs availability, not safety.
- **Prompt Guard 2** missed our image-borne injections and false-fired on human notices; it is only a
  corroborating signal.
- **OCR** (RapidOCR, CPU) misreads some characters (e.g. `l`/`I` in base64), loses spaces in bold fonts,
  and does not handle handwriting or non-Latin scripts. Decoding garbled base64 can be partial.
- **Adaptive attackers** who know the guard could: split text across images, use other languages,
  render text the OCR cannot read but the model can, or phrase injections the classifier accepts.
  The output guard is a second line of defence, not a guarantee.
- **Latency**: ~2–7 s per request on a laptop CPU plus hosted classifiers.
- Weights and thresholds are configurable starting values, calibrated on a small validation set.
