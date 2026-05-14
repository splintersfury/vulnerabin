void __thiscall FUN_1000cfc0(void *this,int *param_1)

{
  _Mtx_internal_imp_t *p_Var1;
  undefined4 *puVar2;
  code *pcVar3;
  undefined4 *puVar4;
  char cVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined *puVar8;
  undefined4 *puVar9;
  int *local_70;
  undefined *local_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined8 local_5c;
  undefined4 local_54 [2];
  _Mtx_internal_imp_t *local_4c;
  int *local_48;
  int *local_44;
  wchar_t *local_40;
  undefined *local_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 local_2c;
  uint uStack_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e72d;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  p_Var1 = (_Mtx_internal_imp_t *)((int)this + 4);
  local_4c = p_Var1;
  local_40 = (wchar_t *)this;
  iVar6 = __Mtx_lock(p_Var1);
  if (iVar6 != 0) {
    FUN_1002d2dd(iVar6);
    goto LAB_1000d1e4;
  }
  local_48 = (int *)((int)this + 0x38);
  puVar2 = (undefined4 *)*local_48;
  cVar5 = *(char *)((int)puVar2[1] + 0xd);
  puVar4 = puVar2;
  puVar9 = (undefined4 *)puVar2[1];
  while (cVar5 == '\0') {
    if ((int *)puVar9[4] < param_1) {
      puVar7 = (undefined4 *)puVar9[2];
      puVar9 = puVar4;
    }
    else {
      puVar7 = (undefined4 *)*puVar9;
    }
    puVar4 = puVar9;
    puVar9 = puVar7;
    cVar5 = *(char *)((int)puVar7 + 0xd);
  }
  local_14 = 0;
  if (((*(char *)((int)puVar4 + 0xd) != '\0') || (param_1 < (int *)puVar4[4])) || (puVar4 == puVar2)
     ) {
    puVar2 = *(undefined4 **)(local_40 + 0x20);
    cVar5 = *(char *)((int)puVar2[1] + 0xd);
    puVar4 = puVar2;
    puVar9 = (undefined4 *)puVar2[1];
    while (cVar5 == '\0') {
      if ((int *)puVar9[4] < param_1) {
        puVar7 = (undefined4 *)puVar9[2];
        puVar9 = puVar4;
      }
      else {
        puVar7 = (undefined4 *)*puVar9;
      }
      puVar4 = puVar9;
      puVar9 = puVar7;
      cVar5 = *(char *)((int)puVar7 + 0xd);
    }
    if (((*(char *)((int)puVar4 + 0xd) != '\0') || (param_1 < (int *)puVar4[4])) ||
       (puVar4 == puVar2)) {
      local_2c = 0;
      uStack_28 = 7;
      local_3c = (undefined *)0x0;
      local_14 = 1;
      cVar5 = FUN_1000d450(local_40,param_1,&local_3c);
      puVar8 = local_3c;
      if (cVar5 == '\0') {
        local_44 = param_1;
        local_40 = L"<error-not-found>";
        FUN_10018b80(local_48,local_54,(uint *)&local_44);
        if (7 < uStack_28) {
          puVar8 = local_3c;
          if ((0xfff < uStack_28 * 2 + 2) &&
             (puVar8 = *(undefined **)(local_3c + -4),
             (undefined *)0x1f < local_3c + (-4 - (int)puVar8))) goto LAB_1000d1e4;
          FUN_1002e346(puVar8);
        }
      }
      else {
        local_70 = param_1;
        local_3c = (undefined *)((uint)local_3c & 0xffff0000);
        local_6c = puVar8;
        uStack_68 = uStack_38;
        uStack_64 = uStack_34;
        uStack_60 = uStack_30;
        local_5c = CONCAT44(uStack_28,local_2c);
        local_2c = 0;
        uStack_28 = 7;
        local_14 = CONCAT31(local_14._1_3_,2);
        FUN_10018a30(local_48,&local_44,(uint *)&local_70);
        if (7 < local_5c._4_4_) {
          puVar8 = local_6c;
          if ((0xfff < local_5c._4_4_ * 2 + 2) &&
             (puVar8 = *(undefined **)(local_6c + -4),
             (undefined *)0x1f < local_6c + (-4 - (int)puVar8))) {
LAB_1000d1e4:
            FUN_10032f7f();
            pcVar3 = (code *)swi(3);
            (*pcVar3)();
            return;
          }
          FUN_1002e346(puVar8);
        }
      }
    }
  }
  __Mtx_unlock((int)p_Var1);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000d1f0 @ 1000d1f0