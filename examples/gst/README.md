# GST Example Corpus

This folder contains focused Phase-4 GST models that use the first-class timing
block:

```trs
timing {
    model: partial_synchrony;
    gst: gst;
}
```

Included models:
- `gst_pbft_view_change_safe.trs`
- `gst_pbft_view_change_buggy.trs`
- `gst_tendermint_liveness_safe.trs`
- `gst_tendermint_liveness_buggy.trs`

These files are intended as focused GST/liveness examples and are separate from
the cert-suite-governed `examples/library` corpus.
