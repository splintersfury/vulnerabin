undefined4 * FUN_10011be0(undefined4 *param_1,int param_2,uint *param_3)

{
  code *pcVar1;
  uint uVar2;
  undefined1 uVar3;
  uint *puVar4;
  undefined4 *puVar5;
  uint *puVar6;
  void *pvVar7;
  uint uVar8;
  void *local_b0 [5];
  uint local_9c;
  void *local_98;
  uint uStack_94;
  uint uStack_90;
  uint uStack_8c;
  undefined8 local_88;
  void *local_80;
  uint uStack_7c;
  uint uStack_78;
  uint uStack_74;
  undefined8 local_70;
  undefined4 *local_68;
  int local_64;
  uint *local_60;
  int local_5c;
  void *local_58;
  uint uStack_54;
  uint uStack_50;
  uint uStack_4c;
  undefined8 local_48;
  uint *local_40;
  void *local_3c [4];
  undefined4 local_2c;
  uint local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004ed0c;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  local_14 = 0;
  local_68 = param_1;
  local_24 = 0;
  local_64 = param_2;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  local_40 = param_3;
  *(undefined1 *)param_1 = 0;
  FUN_10008e70(param_1,(uint *)"syntax error ",0xd);
  uVar8 = 1;
  local_14._0_1_ = 0;
  local_14._1_3_ = 0;
  local_24 = 1;
  if (local_40[4] != 0) {
    puVar4 = FUN_10014120((uint *)&local_80,(uint *)"while parsing ",local_40);
    local_14 = 1;
    puVar4 = FUN_100055a0(puVar4,(uint *)&DAT_1005ef58);
    uVar8 = 3;
    local_24 = 3;
    local_58 = (void *)*puVar4;
    uStack_54 = puVar4[1];
    uStack_50 = puVar4[2];
    uStack_4c = puVar4[3];
    local_48 = *(undefined8 *)(puVar4 + 4);
    puVar4[4] = 0;
    puVar4[5] = 0xf;
    *(undefined1 *)puVar4 = 0;
    local_14._0_1_ = 2;
    FUN_10005610(param_1,(uint *)&local_58);
    local_14._0_1_ = 1;
    uVar3 = (undefined1)local_14;
    local_14._0_1_ = 1;
    if (local_48._4_4_ < 0x10) {
LAB_10011d13:
      local_14._0_1_ = 0;
      if (0xf < local_70._4_4_) {
        pvVar7 = local_80;
        if ((0xfff < local_70._4_4_ + 1) &&
           (pvVar7 = *(void **)((int)local_80 - 4), uVar3 = (undefined1)local_14,
           0x1f < (uint)((int)local_80 + (-4 - (int)pvVar7)))) goto LAB_10012184;
        FUN_1002e346(pvVar7);
      }
      goto LAB_10011d4b;
    }
    pvVar7 = local_58;
    if ((local_48._4_4_ + 1 < 0x1000) ||
       (pvVar7 = *(void **)((int)local_58 - 4), (uint)((int)local_58 + (-4 - (int)pvVar7)) < 0x20))
    {
      FUN_1002e346(pvVar7);
      goto LAB_10011d13;
    }
LAB_10012184:
    local_14._0_1_ = uVar3;
    FUN_10032f7f();
LAB_10012189:
    FUN_10032f7f();
LAB_1001218e:
    FUN_10032f7f();
    goto LAB_10012193;
  }
LAB_10011d4b:
  FUN_100055a0(param_1,(uint *)&DAT_1005ef6c);
  if (*(int *)(local_5c + 0x28) == 0xe) {
    local_60 = (uint *)FUN_100121a0((void *)(local_5c + 0x30),local_b0);
    local_14 = 3;
    local_2c = 0;
    puVar4 = *(uint **)(local_5c + 0x70);
    local_28 = 0xf;
    local_3c[0] = (void *)0x0;
    local_40 = (uint *)((int)puVar4 + 1);
    puVar6 = puVar4;
    do {
      uVar2 = *puVar6;
      puVar6 = (uint *)((int)puVar6 + 1);
    } while ((char)uVar2 != '\0');
    FUN_10008e70(local_3c,puVar4,(int)puVar6 - (int)local_40);
    local_14._0_1_ = 4;
    puVar4 = FUN_100055a0(local_3c,(uint *)"; last read: \'");
    local_24 = uVar8 | 4;
    local_80 = (void *)*puVar4;
    uStack_7c = puVar4[1];
    uStack_78 = puVar4[2];
    uStack_74 = puVar4[3];
    local_70 = *(undefined8 *)(puVar4 + 4);
    puVar4[4] = 0;
    puVar4[5] = 0xf;
    *(undefined1 *)puVar4 = 0;
    local_14._0_1_ = 5;
    FUN_10018020(&local_58,local_68,(uint *)&local_80,local_60);
    local_24 = uVar8 | 0xc;
    local_14._0_1_ = 6;
    puVar4 = FUN_100055a0(&local_58,(uint *)&DAT_1005eec0);
    local_24 = uVar8 | 0x1c;
    local_98 = (void *)*puVar4;
    uStack_94 = puVar4[1];
    uStack_90 = puVar4[2];
    uStack_8c = puVar4[3];
    local_88 = *(undefined8 *)(puVar4 + 4);
    puVar4[4] = 0;
    puVar4[5] = 0xf;
    *(undefined1 *)puVar4 = 0;
    local_14._0_1_ = 7;
    FUN_10005610(param_1,(uint *)&local_98);
    local_14._0_1_ = 6;
    if (0xf < local_88._4_4_) {
      pvVar7 = local_98;
      if ((0xfff < local_88._4_4_ + 1) &&
         (pvVar7 = *(void **)((int)local_98 - 4), 0x1f < (uint)((int)local_98 + (-4 - (int)pvVar7)))
         ) goto LAB_10012189;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 5;
    if (0xf < local_48._4_4_) {
      pvVar7 = local_58;
      if ((0xfff < local_48._4_4_ + 1) &&
         (pvVar7 = *(void **)((int)local_58 - 4), 0x1f < (uint)((int)local_58 + (-4 - (int)pvVar7)))
         ) goto LAB_10012189;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 4;
    local_48 = 0xf00000000;
    local_58 = (void *)((uint)local_58 & 0xffffff00);
    if (0xf < local_70._4_4_) {
      pvVar7 = local_80;
      if ((0xfff < local_70._4_4_ + 1) &&
         (pvVar7 = *(void **)((int)local_80 - 4), 0x1f < (uint)((int)local_80 + (-4 - (int)pvVar7)))
         ) goto LAB_10012189;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 3;
    if (0xf < local_28) {
      pvVar7 = local_3c[0];
      if ((0xfff < local_28 + 1) &&
         (pvVar7 = *(void **)((int)local_3c[0] + -4),
         0x1f < (uint)((int)local_3c[0] + (-4 - (int)pvVar7)))) goto LAB_10012189;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 0;
    local_2c = 0;
    local_28 = 0xf;
    local_3c[0] = (void *)((uint)local_3c[0] & 0xffffff00);
    if (0xf < local_9c) {
      pvVar7 = local_b0[0];
      if ((0xfff < local_9c + 1) &&
         (pvVar7 = *(void **)((int)local_b0[0] + -4),
         0x1f < (uint)((int)local_b0[0] + (-4 - (int)pvVar7)))) goto LAB_10012189;
LAB_10012082:
      local_14._0_1_ = 0;
      FUN_1002e346(pvVar7);
    }
  }
  else {
    puVar6 = (uint *)FUN_10012540(*(int *)(local_5c + 0x28));
    local_2c = 0;
    local_28 = 0xf;
    local_3c[0] = (void *)0x0;
    puVar4 = puVar6;
    do {
      uVar8 = *puVar4;
      puVar4 = (uint *)((int)puVar4 + 1);
    } while ((char)uVar8 != '\0');
    FUN_10008e70(local_3c,puVar6,(int)puVar4 - ((int)puVar6 + 1));
    local_14 = 8;
    puVar4 = FUN_10005f20((uint *)&local_58,(uint *)"unexpected ",(uint *)local_3c);
    local_14._0_1_ = 9;
    FUN_10005610(param_1,puVar4);
    local_14._0_1_ = 8;
    if (0xf < local_48._4_4_) {
      pvVar7 = local_58;
      if ((0xfff < local_48._4_4_ + 1) &&
         (pvVar7 = *(void **)((int)local_58 - 4), 0x1f < (uint)((int)local_58 + (-4 - (int)pvVar7)))
         ) goto LAB_1001218e;
      FUN_1002e346(pvVar7);
    }
    local_14._0_1_ = 0;
    local_48 = 0xf00000000;
    local_58 = (void *)((uint)local_58 & 0xffffff00);
    if (0xf < local_28) {
      pvVar7 = local_3c[0];
      if ((0xfff < local_28 + 1) &&
         (pvVar7 = *(void **)((int)local_3c[0] + -4),
         0x1f < (uint)((int)local_3c[0] + (-4 - (int)pvVar7)))) goto LAB_1001218e;
      goto LAB_10012082;
    }
  }
  if (local_64 != 0) {
    puVar6 = (uint *)FUN_10012540(local_64);
    local_2c = 0;
    local_28 = 0xf;
    local_3c[0] = (void *)0x0;
    puVar4 = puVar6;
    do {
      uVar8 = *puVar4;
      puVar4 = (uint *)((int)puVar4 + 1);
    } while ((char)uVar8 != '\0');
    FUN_10008e70(local_3c,puVar6,(int)puVar4 - ((int)puVar6 + 1));
    local_14 = 10;
    puVar4 = FUN_10005f20((uint *)&local_58,(uint *)"; expected ",(uint *)local_3c);
    local_14._0_1_ = 0xb;
    FUN_10005610(param_1,puVar4);
    if (0xf < local_48._4_4_) {
      pvVar7 = local_58;
      if ((0xfff < local_48._4_4_ + 1) &&
         (pvVar7 = *(void **)((int)local_58 - 4), 0x1f < (uint)((int)local_58 + (-4 - (int)pvVar7)))
         ) goto LAB_10012193;
      FUN_1002e346(pvVar7);
    }
    local_48 = 0xf00000000;
    local_58 = (void *)((uint)local_58 & 0xffffff00);
    if (0xf < local_28) {
      pvVar7 = local_3c[0];
      if ((0xfff < local_28 + 1) &&
         (pvVar7 = *(void **)((int)local_3c[0] + -4),
         0x1f < (uint)((int)local_3c[0] + (-4 - (int)pvVar7)))) {
LAB_10012193:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        puVar5 = (undefined4 *)(*pcVar1)();
        return puVar5;
      }
      FUN_1002e346(pvVar7);
    }
  }
  ExceptionList = local_1c;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100121a0 @ 100121a0