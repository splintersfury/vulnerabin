void __thiscall FUN_1002c2f0(void *this,undefined4 *param_1,undefined4 param_2)

{
  int *piVar1;
  uint uVar2;
  undefined **ppuVar3;
  undefined *puVar4;
  int iVar5;
  undefined **extraout_ECX;
  int local_3c [5];
  undefined4 *local_28;
  undefined4 local_24;
  int local_20;
  undefined **local_1c;
  int *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050dbb;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_28 = param_1;
  local_24 = param_2;
  local_14 = uVar2;
  if ((*(int *)(*(int *)((int)ThreadLocalStoragePointer + _tls_index * 4) + 4) < DAT_1006b730) &&
     (FUN_1002ec60(&DAT_1006b730), DAT_1006b730 == -1)) {
    local_8 = 0;
    DAT_1006b734 = (undefined **)0x0;
    ppuVar3 = (undefined **)operator_new(0xc);
    local_8._0_1_ = 1;
    local_1c = ppuVar3;
    if (ppuVar3 != (undefined **)0x0) {
      ppuVar3[0] = (undefined *)0x0;
      ppuVar3[1] = (undefined *)0x0;
      ppuVar3[2] = (undefined *)0x0;
      ppuVar3[1] = (undefined *)0x0;
      ppuVar3[2] = (undefined *)0x1;
      puVar4 = (undefined *)Ordinal_2(&DAT_10061668);
      *ppuVar3 = puVar4;
      if (puVar4 != (undefined *)0x0) goto LAB_1002c3c0;
      goto LAB_1002c4c6;
    }
    ppuVar3 = (undefined **)0x0;
LAB_1002c3c0:
    local_8._0_1_ = 0;
    DAT_1006b734 = ppuVar3;
    if (ppuVar3 != (undefined **)0x0) {
      _atexit(FUN_10051000);
      FUN_1002ec16(&DAT_1006b730);
      param_2 = local_24;
      goto LAB_1002c3ef;
    }
  }
  else {
LAB_1002c3ef:
    local_18 = (int *)0x0;
    local_8._0_1_ = 2;
    local_8._1_3_ = 0;
    piVar1 = *(int **)((int)this + 4);
    if (piVar1 != (int *)0x0) {
      local_8 = 2;
      local_18 = (int *)0x0;
      if (DAT_1006b734 == (undefined **)0x0) {
        puVar4 = (undefined *)0x0;
      }
      else {
        puVar4 = *DAT_1006b734;
      }
      iVar5 = (**(code **)(*piVar1 + 0x50))(piVar1,puVar4,param_2,0x30,0,&local_18,uVar2);
      if (iVar5 != 0) {
        FUN_1002c1c0(local_3c,iVar5);
                    /* WARNING: Subroutine does not return */
        __CxxThrowException_8(local_3c,&DAT_10067674);
      }
      *param_1 = local_18;
      local_8._0_1_ = 4;
      if (local_18 != (int *)0x0) {
        (**(code **)(*local_18 + 4))(local_18);
      }
      param_1[1] = 0;
      local_8._0_1_ = 6;
      local_20 = 0;
      local_1c = &PTR_vftable_10069aa8;
      FUN_1002bde0(param_1,&local_20);
      iVar5 = local_20;
      ppuVar3 = local_1c;
      if ((local_1c[1] == DAT_10069aac) && (local_20 == 0)) {
        local_8 = 7;
        if (local_18 != (int *)0x0) {
          (**(code **)(*local_18 + 8))(local_18);
        }
        ExceptionList = local_10;
        FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
        return;
      }
      goto LAB_1002c4da;
    }
    FUN_1002f620(0x80004003);
LAB_1002c4c6:
    FUN_1002f620(0x8007000e);
  }
  iVar5 = FUN_1002f620(0x8007000e);
  ppuVar3 = extraout_ECX;
LAB_1002c4da:
  FUN_10027cd0(local_3c,(uint *)"objects_iterator::increment failed",iVar5,(int *)ppuVar3);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_3c,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c520 @ 1002c520