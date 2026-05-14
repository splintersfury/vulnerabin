undefined8 * FUN_140003820(undefined8 *param_1,LPCWSTR param_2,undefined8 *param_3)

{
  DWORD DVar1;
  HMODULE pHVar2;
  undefined4 uStack_14;
  
  pHVar2 = LoadLibraryW(param_2);
  if (pHVar2 == (HMODULE)0x0) {
    DVar1 = GetLastError();
    *param_3 = CONCAT44(uStack_14,DVar1);
    param_3[1] = &PTR_vftable_14007ad08;
  }
  else {
    *(undefined4 *)param_3 = 0;
    param_3[1] = &PTR_vftable_14007ac70;
  }
  *param_1 = pHVar2;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140003890 @ 140003890