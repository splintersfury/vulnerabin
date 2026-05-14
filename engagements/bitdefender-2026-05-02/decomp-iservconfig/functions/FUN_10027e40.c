void __fastcall
FUN_10027e40(HCRYPTHASH *param_1,HCRYPTPROV *param_2,undefined4 param_3,HCRYPTKEY *param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  undefined **ppuVar3;
  int local_40 [5];
  HCRYPTHASH *local_2c;
  undefined4 local_28;
  HCRYPTHASH local_24;
  undefined8 local_20;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005051e;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_28 = 0;
  local_20 = 0;
  local_24 = 0;
  local_2c = param_1;
  BVar1 = CryptCreateHash(*param_2,0x8004,*param_4,0,&local_24);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    ppuVar3 = &PTR_vftable_10069ab8;
  }
  else {
    ppuVar3 = &PTR_vftable_10069aa8;
    DVar2 = (DWORD)local_20;
  }
  *param_1 = local_24;
  local_8 = 0;
  local_28 = 1;
  if ((ppuVar3[1] == DAT_10069aac) && (DVar2 == 0)) {
    ExceptionList = local_10;
    FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_10027cd0(local_40,(uint *)"CryptCreateHash failed",DVar2,(int *)ppuVar3);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_40,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: FUN_10027f20 @ 10027f20