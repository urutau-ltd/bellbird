((nil . ((fill-column . 100)
         (indent-tabs-mode . nil)
         (tab-width . 2)
         (require-final-newline . t)
         (sentence-end-double-space . nil)
         (show-trailing-whitespace . t)
         (compile-command . "guix shell --network -m ./manifest.scm -- make verify")))

 (go-mode . ((indent-tabs-mode . t)
             (tab-width . 8)
             (compile-command . "guix shell --network -m ./manifest.scm -- make ci")
             (gofmt-command . "gofmt")
             (eglot-workspace-configuration
              . (:gopls
                 ((gofumpt t)
                  (staticcheck t)
                  (completeUnimported t)
                  (usePlaceholders t)
                  (directoryFilters ["-build" "-.cache" "-.git"])
                  (hints
                   ((assignVariableTypes t)
                    (compositeLiteralFields t)
                    (compositeLiteralTypes t)
                    (constantValues t)
                    (functionTypeParameters t)
                    (parameterNames t)
                    (rangeVariableTypes t)))
                  (analyses
                   ((fieldalignment t)
                    (nilness t)
                    (unusedparams t)
                    (unusedwrite t))))))))

 (go-mod-ts-mode . ((indent-tabs-mode . t)
                    (tab-width . 8)))

 (go-work-ts-mode . ((indent-tabs-mode . t)
                     (tab-width . 8)))

 (makefile-mode . ((indent-tabs-mode . t)
                   (tab-width . 8)))

 (sh-mode . ((sh-basic-offset . 2)
             (sh-indentation . 2)
             (indent-tabs-mode . nil)))

 (markdown-mode . ((fill-column . 80)
                   (indent-tabs-mode . nil)))

 (text-mode . ((fill-column . 80)
               (indent-tabs-mode . nil)))

 (scheme-mode . ((indent-tabs-mode . nil)
                 (tab-width . 2)))

 (emacs-lisp-mode . ((indent-tabs-mode . nil)
                     (tab-width . 2))))
