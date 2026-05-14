DWORD __fastcall FUN_10004630(int param_1)

{
  HMODULE pHVar1;
  BOOL BVar2;
  DWORD DVar3;
  FARPROC pFVar4;
  int iVar5;
  
  FUN_100059d0(param_1);
  FUN_10001d40((void *)(param_1 + 0x18),(uint *)L"productinfo",0xb);
  pHVar1 = LoadLibraryW(L"IServConfig.dll");
  *(HMODULE *)(param_1 + 4) = pHVar1;
  if ((pHVar1 == (HMODULE)0x0) && (BVar2 = PathIsRelativeW(L"IServConfig.dll"), BVar2 == 0)) {
    pHVar1 = LoadLibraryExW(L"IServConfig.dll",(HANDLE)0x0,8);
    *(HMODULE *)(param_1 + 4) = pHVar1;
  }
  if (*(HMODULE *)(param_1 + 4) != (HMODULE)0x0) {
    pFVar4 = GetProcAddress(*(HMODULE *)(param_1 + 4),"BdCreateObject");
    *(FARPROC *)(param_1 + 0x14) = pFVar4;
    if (pFVar4 != (FARPROC)0x0) {
      pFVar4 = GetProcAddress(*(HMODULE *)(param_1 + 4),"BdDestroyObject");
      *(FARPROC *)(param_1 + 0x10) = pFVar4;
      if (pFVar4 != (FARPROC)0x0) {
        DVar3 = (**(code **)(param_1 + 0x14))
                          (L"productinfo",0x66551ab3,0xbc90fca3,0xf7c5425f,0x514be292,
                           (undefined4 *)(param_1 + 8));
        if (DVar3 == 0) {
          iVar5 = (**(code **)**(undefined4 **)(param_1 + 8))
                            (0x5666c9d0,0x666b9724,0x61084666,0xf666c93d);
          *(int *)(param_1 + 0xc) = iVar5;
          if (iVar5 != 0) {
            return 0;
          }
          DVar3 = 0x278;
        }
        goto LAB_10004737;
      }
    }
  }
  DVar3 = GetLastError();
  if (DVar3 == 0) {
    FUN_100059d0(param_1);
    return 0x278;
  }
LAB_10004737:
  FUN_100059d0(param_1);
  return DVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004750 @ 10004750