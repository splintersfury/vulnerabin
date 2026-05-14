void FUN_1400083c0(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  code *pcVar2;
  char *pcVar3;
  int iVar4;
  longlong *plVar5;
  undefined8 uVar6;
  undefined8 ****ppppuVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined1 auStack_1a8 [32];
  longlong local_188 [2];
  undefined8 local_178;
  ulonglong local_170;
  longlong local_168 [2];
  undefined8 local_158;
  ulonglong local_150;
  longlong local_148 [2];
  undefined8 local_138;
  ulonglong local_130;
  undefined8 ***local_128;
  undefined8 uStack_120;
  ulonglong local_118;
  ulonglong uStack_110;
  undefined4 local_108 [2];
  undefined8 ***local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  code *local_e8;
  undefined8 local_e0;
  undefined1 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 uStack_c0;
  char *local_b8;
  undefined8 ***local_b0;
  undefined8 uStack_a8;
  ulonglong local_a0;
  ulonglong uStack_98;
  undefined8 ***local_90 [2];
  undefined8 local_80;
  ulonglong uStack_78;
  undefined8 *local_70;
  undefined **local_68;
  undefined8 ***local_60 [3];
  ulonglong local_48;
  char local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_1a8;
  local_b8 = "bdch-{35312C50-89A4-4885-821E-BB3C4F471D64}";
  ppppuVar7 = (undefined8 ****)0x0;
  local_a0 = 0;
  uStack_98 = 7;
  local_b0 = (undefined8 ****)0x0;
  puVar1 = *(undefined8 **)(param_1 + 0x20);
  uVar8 = 0xffffffffffffffff;
  uVar9 = uVar8;
  if (puVar1 == (undefined8 *)0x0) {
    local_70 = (undefined8 *)0x0;
    local_68 = &PTR_vftable_14007ac70;
    FUN_1400067c0(&local_128,&local_70,param_3);
    if (uStack_98 < 8) {
LAB_1400084a2:
      local_b0 = local_128;
      uStack_a8 = uStack_120;
      local_a0 = local_118;
      uStack_98 = uStack_110;
      goto LAB_1400084b2;
    }
    if ((uStack_98 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)local_b0 + (-8 - (longlong)local_b0[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_1400084a2;
    }
  }
  else {
    do {
      uVar9 = uVar9 + 1;
    } while (*(short *)((longlong)puVar1 + uVar9 * 2) != 0);
    FUN_140010340((longlong *)&local_b0,puVar1,uVar9);
LAB_1400084b2:
    local_b8 = (char *)0x0;
    if ((local_a0 != 0) && (ppppuVar7 = &local_b0, 7 < uStack_98)) {
      ppppuVar7 = (undefined8 ****)local_b0;
    }
    FUN_140006fc0(&local_b8,ppppuVar7);
    pcVar3 = local_b8;
    if (local_b8 == (char *)0x0) {
LAB_1400088f8:
      if (pcVar3 != (char *)0x0) {
        if (*(HMODULE *)pcVar3 != (HMODULE)0x0) {
          FreeLibrary(*(HMODULE *)pcVar3);
          pcVar3[0] = '\0';
          pcVar3[1] = '\0';
          pcVar3[2] = '\0';
          pcVar3[3] = '\0';
          pcVar3[4] = '\0';
          pcVar3[5] = '\0';
          pcVar3[6] = '\0';
          pcVar3[7] = '\0';
        }
        FUN_14002f180();
      }
      if (uStack_98 < 8) {
LAB_140008958:
        FUN_14002f160(local_38 ^ (ulonglong)auStack_1a8);
        return;
      }
      if ((uStack_98 * 2 + 2 < 0x1000) ||
         ((ulonglong)((longlong)local_b0 + (-8 - (longlong)local_b0[-1])) < 0x20)) {
        FUN_14002f180();
        goto LAB_140008958;
      }
      FUN_140035d28();
    }
    else {
      ppppuVar7 = &local_b0;
      if (7 < uStack_98) {
        ppppuVar7 = (undefined8 ****)local_b0;
      }
      local_80 = 0;
      uStack_78 = 7;
      local_90[0] = (undefined8 ****)0x0;
      FUN_140010340((longlong *)local_90,ppppuVar7,local_a0);
      puVar1 = *(undefined8 **)(param_1 + 0x10);
      uVar9 = uVar8;
      if (puVar1 == (undefined8 *)0x0) {
        do {
          uVar9 = uVar9 + 1;
        } while (*(short *)(PTR_u_bdch_json_14006b6d0 + uVar9 * 2) != 0);
        local_178 = 0;
        local_170 = 7;
        local_188[0] = 0;
        FUN_140010340(local_188,(undefined8 *)PTR_u_bdch_json_14006b6d0,uVar9);
        FUN_1400054f0((uint *)local_90,(uint *)local_188,uVar9);
        if (7 < local_170) {
          if ((0xfff < local_170 * 2 + 2) &&
             (0x1f < (local_188[0] - *(longlong *)(local_188[0] + -8)) - 8U)) goto LAB_140008994;
LAB_14000863b:
          FUN_14002f180();
        }
LAB_140008640:
        if (*(char *)(param_1 + 0x68) != '\0') {
          plVar5 = (longlong *)FUN_140008300();
          if (*(char *)(param_1 + 0x68) == '\0') {
            std::_Throw_parallelism_resources_exhausted();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
          puVar1 = (undefined8 *)plVar5[1];
          if (puVar1 == (undefined8 *)plVar5[2]) {
            FUN_140012cc0(plVar5,puVar1,param_1 + 0x28);
          }
          else {
            puVar1[7] = 0;
            local_70 = puVar1;
            if (*(longlong *)(param_1 + 0x60) != 0) {
              uVar6 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                                (*(longlong *)(param_1 + 0x60),puVar1);
              puVar1[7] = uVar6;
            }
            plVar5[1] = plVar5[1] + 0x40;
          }
        }
        local_108[0] = 0x10000;
        local_100 = local_90;
        if (7 < uStack_78) {
          local_100 = local_90[0];
        }
        local_f8 = *(undefined8 *)(param_1 + 8);
        local_f0 = 0;
        local_e8 = FUN_140008370;
        local_e0 = 0;
        local_d8 = 1;
        local_d0 = *(undefined8 *)(param_1 + 0x18);
        local_c8 = 0;
        uStack_c0 = 0;
        iVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_108);
        if (iVar4 == 0) {
LAB_14000882a:
          signal(0x16);
          signal(0xf);
        }
        else {
          ppppuVar7 = &local_b0;
          if (7 < uStack_98) {
            ppppuVar7 = (undefined8 ****)local_b0;
          }
          local_148[0] = 0;
          local_138 = 0;
          local_130 = 7;
          FUN_140010340(local_148,ppppuVar7,local_a0);
          FUN_14000e6b0((longlong *)local_90,local_148);
          if (7 < local_130) {
            if ((0xfff < local_130 * 2 + 2) &&
               (0x1f < (local_148[0] - *(longlong *)(local_148[0] + -8)) - 8U)) {
              FUN_140035d28();
              pcVar2 = (code *)swi(3);
              (*pcVar2)();
              return;
            }
            FUN_14002f180();
          }
          do {
            uVar8 = uVar8 + 1;
          } while (*(short *)(PTR_DAT_14006b6c0 + uVar8 * 2) != 0);
          local_158 = 0;
          local_150 = 7;
          local_168[0] = 0;
          FUN_140010340(local_168,(undefined8 *)PTR_DAT_14006b6c0,uVar8);
          FUN_1400054f0((uint *)local_90,(uint *)local_168,uVar8);
          uVar9 = local_150;
          if (7 < local_150) {
            uVar9 = local_150 * 2 + 2;
            if ((0xfff < uVar9) &&
               (uVar9 = local_150 * 2 + 0x29,
               0x1f < (local_168[0] - *(longlong *)(local_168[0] + -8)) - 8U)) {
              FUN_140035d28();
              goto LAB_1400089ac;
            }
            FUN_14002f180();
          }
          local_100 = local_90;
          if (7 < uStack_78) {
            local_100 = local_90[0];
          }
          iVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_108);
          if (iVar4 == 0) goto LAB_14000882a;
          FUN_140008220((longlong *)local_60,uVar9,uVar8);
          if (local_40 != '\0') {
            local_100 = local_60;
            if (7 < local_48) {
              local_100 = local_60[0];
            }
            iVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)(local_108);
            if (iVar4 == 0) {
              signal(0x16);
              signal(0xf);
            }
          }
          FUN_14000d470((longlong *)local_60);
        }
        if (7 < uStack_78) {
          if ((0xfff < uStack_78 * 2 + 2) &&
             (0x1f < (ulonglong)((longlong)local_90[0] + (-8 - (longlong)local_90[0][-1])))) {
LAB_1400089ac:
            FUN_140035d28();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
          FUN_14002f180();
        }
        local_80 = _DAT_14006e180;
        uStack_78 = _UNK_14006e188;
        local_90[0] = (undefined8 ***)((ulonglong)local_90[0] & 0xffffffffffff0000);
        goto LAB_1400088f8;
      }
      do {
        uVar9 = uVar9 + 1;
      } while (*(short *)((longlong)puVar1 + uVar9 * 2) != 0);
      local_178 = 0;
      local_170 = 7;
      local_188[0] = 0;
      FUN_140010340(local_188,puVar1,uVar9);
      FUN_1400054f0((uint *)local_90,(uint *)local_188,uVar9);
      if (local_170 < 8) goto LAB_140008640;
      if ((local_170 * 2 + 2 < 0x1000) ||
         ((local_188[0] - *(longlong *)(local_188[0] + -8)) - 8U < 0x20)) goto LAB_14000863b;
    }
    FUN_140035d28();
  }
  FUN_140035d28();
LAB_140008994:
  FUN_140035d28();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400089c0 @ 1400089c0