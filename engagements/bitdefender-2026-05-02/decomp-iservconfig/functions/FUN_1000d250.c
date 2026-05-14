void __thiscall FUN_1000d250(void *this,uint param_1)

{
  _Mtx_internal_imp_t *p_Var1;
  code *pcVar2;
  undefined4 *puVar3;
  char cVar4;
  int iVar5;
  undefined4 *puVar6;
  wchar_t *this_00;
  uint ******ppppppuVar7;
  undefined4 *puVar8;
  uint local_5c;
  uint ******local_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined8 local_48;
  _Mtx_internal_imp_t *local_40;
  undefined4 local_3c [2];
  uint local_34;
  wchar_t *local_30;
  uint ******local_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 local_1c;
  uint uStack_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e77d;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  p_Var1 = (_Mtx_internal_imp_t *)((int)this + 4);
  local_40 = p_Var1;
  iVar5 = __Mtx_lock(p_Var1);
  if (iVar5 != 0) {
    FUN_1002d2dd(iVar5);
LAB_1000d440:
    FUN_10032f7f();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  local_30 = (wchar_t *)((int)this + 0x48);
  puVar8 = (undefined4 *)(*(undefined4 **)local_30)[1];
  cVar4 = *(char *)((int)puVar8 + 0xd);
  puVar3 = *(undefined4 **)local_30;
  while (cVar4 == '\0') {
    if ((uint)puVar8[4] < param_1) {
      puVar6 = (undefined4 *)puVar8[2];
      puVar8 = puVar3;
    }
    else {
      puVar6 = (undefined4 *)*puVar8;
    }
    puVar3 = puVar8;
    puVar8 = puVar6;
    cVar4 = *(char *)((int)puVar6 + 0xd);
  }
  if (((*(char *)((int)puVar3 + 0xd) == '\0') && ((uint)puVar3[4] <= param_1)) &&
     (puVar3 != *(undefined4 **)local_30)) {
    local_8 = 0;
  }
  else {
    local_1c = 0;
    uStack_18 = 7;
    local_2c = (uint ******)0x0;
    local_8 = 1;
    this_00 = local_30;
    if ((param_1 < 7) &&
       (cVar4 = FUN_10003650(param_1,&local_2c), this_00 = local_30, cVar4 != '\0')) {
      local_5c = param_1;
      local_58 = local_2c;
      uStack_54 = uStack_28;
      uStack_50 = uStack_24;
      uStack_4c = uStack_20;
      local_2c = (uint ******)((uint)local_2c & 0xffff0000);
      local_48 = CONCAT44(uStack_18,local_1c);
      local_1c = 0;
      uStack_18 = 7;
      local_8 = CONCAT31(local_8._1_3_,2);
      FUN_10018a30(local_30,local_3c,&local_5c);
      if (7 < local_48._4_4_) {
        ppppppuVar7 = local_58;
        if ((0xfff < local_48._4_4_ * 2 + 2) &&
           (ppppppuVar7 = (uint ******)local_58[-1],
           0x1f < (uint)((int)local_58 + (-4 - (int)ppppppuVar7)))) goto LAB_1000d440;
        FUN_1002e346(ppppppuVar7);
      }
    }
    else {
      local_34 = param_1;
      local_30 = L"<error-not-found>";
      FUN_10018b80(this_00,local_3c,&local_34);
    }
    if (7 < uStack_18) {
      ppppppuVar7 = local_2c;
      if ((0xfff < uStack_18 * 2 + 2) &&
         (ppppppuVar7 = (uint ******)local_2c[-1],
         0x1f < (uint)((int)local_2c + (-4 - (int)ppppppuVar7)))) goto LAB_1000d440;
      FUN_1002e346(ppppppuVar7);
    }
    local_1c = 0;
    uStack_18 = 7;
    local_2c = (uint ******)((uint)local_2c & 0xffff0000);
  }
  __Mtx_unlock((int)p_Var1);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000d450 @ 1000d450