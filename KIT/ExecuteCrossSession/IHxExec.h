#ifndef IHXEXEC_H
#define IHXEXEC_H

// Define the IHxHelpPaneServer interface in C
typedef struct IHxHelpPaneServer IHxHelpPaneServer;

typedef struct IHxHelpPaneServerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IHxHelpPaneServer *This, REFIID riid, void **ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IHxHelpPaneServer *This);
    ULONG (STDMETHODCALLTYPE *Release)(IHxHelpPaneServer *This);
    HRESULT (STDMETHODCALLTYPE *DisplayTask)(IHxHelpPaneServer *This, PWCHAR);
    HRESULT (STDMETHODCALLTYPE *DisplayContents)(IHxHelpPaneServer *This, PWCHAR);
    HRESULT (STDMETHODCALLTYPE *DisplaySearchResults)(IHxHelpPaneServer *This, PWCHAR);
    HRESULT (STDMETHODCALLTYPE *Execute)(IHxHelpPaneServer *This, const PWCHAR);
} IHxHelpPaneServerVtbl;

struct IHxHelpPaneServer {
    IHxHelpPaneServerVtbl *lpVtbl;
};

#endif // IHXEXEC_H
