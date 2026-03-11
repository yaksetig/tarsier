import Lake
open Lake DSL

package «tarsier-kernel-formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib TarsierKernel where
  srcDir := "TarsierKernel"
  roots := #[`Basic]
