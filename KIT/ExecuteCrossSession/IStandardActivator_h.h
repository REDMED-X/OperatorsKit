#ifndef __ISTANDARD_ACTIVATOR_H_H__
#define __ISTANDARD_ACTIVATOR_H_H__

#include <windows.h>
#include <unknwn.h>

#ifdef __cplusplus
extern "C"{
#endif 

/* Forward Declarations */ 

#ifndef __IStandardActivator_FWD_DEFINED__
#define __IStandardActivator_FWD_DEFINED__
typedef interface IStandardActivator IStandardActivator;
#endif 	/* __IStandardActivator_FWD_DEFINED__ */


#ifndef __ISpecialSystemProperties_FWD_DEFINED__
#define __ISpecialSystemProperties_FWD_DEFINED__
typedef interface ISpecialSystemProperties ISpecialSystemProperties;
#endif 	/* __ISpecialSystemProperties_FWD_DEFINED__ */


/* interface IStandardActivator */
/* [unique][uuid][local][object] */ 

EXTERN_C const IID IID_IStandardActivator;

typedef struct IStandardActivatorVtbl {
    BEGIN_INTERFACE
    
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        IStandardActivator * This,
        /* [in] */ REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    
    ULONG ( STDMETHODCALLTYPE *AddRef )( 
        IStandardActivator * This);
    
    ULONG ( STDMETHODCALLTYPE *Release )( 
        IStandardActivator * This);
    
    HRESULT ( STDMETHODCALLTYPE *StandardGetClassObject )( 
        IStandardActivator * This,
        /* [in] */ REFCLSID rclsid,
        /* [in] */ DWORD dwClsCtx,
        /* [in] */ COSERVERINFO *pServerInfo,
        /* [in] */ REFIID riid,
        /* [iid_is][out] */ void **ppv);
    
    HRESULT ( STDMETHODCALLTYPE *StandardCreateInstance )( 
        IStandardActivator * This,
        /* [in] */ REFCLSID Clsid,
        /* [in] */ IUnknown *punkOuter,
        /* [in] */ DWORD dwClsCtx,
        /* [in] */ COSERVERINFO *pServerInfo,
        /* [in] */ DWORD dwCount,
        /* [size_is][in] */ MULTI_QI *pResults);
    
    END_INTERFACE
} IStandardActivatorVtbl;

interface IStandardActivator {
    CONST_VTBL struct IStandardActivatorVtbl *lpVtbl;
};


/* interface ISpecialSystemProperties */
/* [unique][uuid][local][object] */ 

EXTERN_C const IID IID_ISpecialSystemProperties;

typedef struct ISpecialSystemPropertiesVtbl {
    BEGIN_INTERFACE
    
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        ISpecialSystemProperties * This,
        /* [in] */ REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    
    ULONG ( STDMETHODCALLTYPE *AddRef )( 
        ISpecialSystemProperties * This);
    
    ULONG ( STDMETHODCALLTYPE *Release )( 
        ISpecialSystemProperties * This);
    
    HRESULT ( STDMETHODCALLTYPE *SetSessionId )( 
        ISpecialSystemProperties * This,
        /* [in] */ ULONG dwSessionId,
        /* [in] */ BOOL bUseConsole,
        /* [in] */ BOOL fRemoteThisSessionId);
    
    END_INTERFACE
} ISpecialSystemPropertiesVtbl;

interface ISpecialSystemProperties {
    CONST_VTBL struct ISpecialSystemPropertiesVtbl *lpVtbl;
};

#ifdef __cplusplus
}
#endif

#endif  /* __ISTANDARD_ACTIVATOR_H_H__ */
