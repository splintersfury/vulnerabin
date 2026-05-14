void __fastcall FUN_1000a2e0(uint *param_1,uint *param_2,uint param_3)

{
  code *pcVar1;
  uint uVar2;
  undefined1 *puVar3;
  void *pvVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  void *local_8c [4];
  undefined4 local_7c;
  uint local_78;
  void *local_74 [4];
  undefined4 local_64;
  uint local_60;
  void *local_5c [4];
  undefined4 local_4c;
  uint local_48;
  uint *local_44;
  uint *local_40;
  void *local_3c;
  uint uStack_38;
  uint uStack_34;
  uint uStack_30;
  undefined1 local_2c [5];
  undefined1 auStack_27 [7];
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e325;
  local_1c = ExceptionList;
  auStack_27._3_4_ = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  puVar8 = (uint *)(local_2c + 5);
  if ((int)param_3 < 0) {
    uVar6 = -param_3;
    do {
      puVar7 = puVar8;
      puVar8 = (uint *)((int)puVar7 + -1);
      uVar5 = uVar6 / 10;
      *(char *)puVar8 = (char)uVar6 + (char)uVar5 * -10 + '0';
      uVar6 = uVar5;
    } while (uVar5 != 0);
    puVar8 = (uint *)((int)puVar7 + -2);
    *(char *)puVar8 = '-';
  }
  else {
    do {
      puVar8 = (uint *)((int)puVar8 + -1);
      uVar6 = param_3 / 10;
      *(char *)puVar8 = (char)param_3 + (char)uVar6 * -10 + '0';
      param_3 = uVar6;
    } while (uVar6 != 0);
  }
  local_4c = 0;
  local_48 = 0xf;
  local_5c[0] = (void *)0x0;
  local_44 = param_2;
  local_40 = param_1;
  puVar3 = &stack0xfffffffc;
  if (puVar8 != (uint *)(local_2c + 5)) {
    FUN_10008e70(local_5c,puVar8,(int)(local_2c + 5) - (int)puVar8);
    puVar3 = puStack_20;
  }
  puStack_20 = puVar3;
  local_14 = 0;
  puVar8 = FUN_10014120((uint *)local_8c,(uint *)"[json.exception.",local_44);
  local_14._0_1_ = 1;
  puVar8 = FUN_100055a0(puVar8,(uint *)&DAT_1005e2ac);
  local_3c = (void *)*puVar8;
  uStack_38 = puVar8[1];
  uStack_34 = puVar8[2];
  uStack_30 = puVar8[3];
  _local_2c = *(undefined8 *)(puVar8 + 4);
  puVar8[4] = 0;
  puVar8[5] = 0xf;
  *(undefined1 *)puVar8 = 0;
  local_14._0_1_ = 2;
  FUN_10018020(local_74,local_40,(uint *)&local_3c,(uint *)local_5c);
  local_14 = CONCAT31(local_14._1_3_,3);
  puVar8 = FUN_100055a0(local_74,(uint *)&DAT_1005e96c);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  uVar6 = puVar8[1];
  uVar5 = puVar8[2];
  uVar2 = puVar8[3];
  *param_1 = *puVar8;
  param_1[1] = uVar6;
  param_1[2] = uVar5;
  param_1[3] = uVar2;
  *(undefined8 *)(param_1 + 4) = *(undefined8 *)(puVar8 + 4);
  puVar8[4] = 0;
  puVar8[5] = 0xf;
  *(undefined1 *)puVar8 = 0;
  if (0xf < local_60) {
    pvVar4 = local_74[0];
    if (0xfff < local_60 + 1) {
      pvVar4 = *(void **)((int)local_74[0] + -4);
      if (0x1f < (uint)((int)local_74[0] + (-4 - (int)pvVar4))) goto LAB_1000a564;
    }
    FUN_1002e346(pvVar4);
  }
  local_64 = 0;
  local_60 = 0xf;
  local_74[0] = (void *)((uint)local_74[0] & 0xffffff00);
  if (0xf < stack0xffffffd8) {
    pvVar4 = local_3c;
    if (0xfff < stack0xffffffd8 + 1) {
      pvVar4 = *(void **)((int)local_3c - 4);
      if (0x1f < (uint)((int)local_3c + (-4 - (int)pvVar4))) goto LAB_1000a564;
    }
    FUN_1002e346(pvVar4);
  }
  if (0xf < local_78) {
    pvVar4 = local_8c[0];
    if (0xfff < local_78 + 1) {
      pvVar4 = *(void **)((int)local_8c[0] + -4);
      if (0x1f < (uint)((int)local_8c[0] + (-4 - (int)pvVar4))) goto LAB_1000a564;
    }
    FUN_1002e346(pvVar4);
  }
  local_7c = 0;
  local_78 = 0xf;
  local_8c[0] = (void *)((uint)local_8c[0] & 0xffffff00);
  if (0xf < local_48) {
    pvVar4 = local_5c[0];
    if (0xfff < local_48 + 1) {
      pvVar4 = *(void **)((int)local_5c[0] + -4);
      if (0x1f < (uint)((int)local_5c[0] + (-4 - (int)pvVar4))) {
LAB_1000a564:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    FUN_1002e346(pvVar4);
  }
  ExceptionList = local_1c;
  FUN_1002e315(auStack_27._3_4_ ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000a570 @ 1000a570