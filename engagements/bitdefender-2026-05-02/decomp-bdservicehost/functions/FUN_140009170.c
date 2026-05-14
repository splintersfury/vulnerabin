void FUN_140009170(longlong param_1,undefined8 *param_2,undefined4 param_3,undefined8 param_4)

{
  longlong lVar1;
  code *pcVar2;
  int iVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined2 *puVar9;
  undefined8 uVar10;
  undefined1 auStackY_c8 [32];
  undefined8 uStack_90;
  undefined8 local_78;
  undefined8 uStack_70;
  ulonglong local_68;
  ulonglong uStack_60;
  uint local_58;
  undefined8 *local_50;
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_c8;
  local_58 = 0;
  uVar10 = param_4;
  local_50 = param_2;
  iVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                    (*(undefined8 *)(param_1 + 0x18),param_3,param_4,0);
  if (iVar3 != 0) {
    if (iVar3 != 0x7a) {
      *(undefined1 *)(param_2 + 4) = 0;
      goto LAB_1400093e9;
    }
    local_68 = 0;
    uStack_60 = 7;
    if (1 < local_58) {
      local_78 = (undefined8 *)0x0;
      uVar7 = (ulonglong)local_58;
      if (local_58 == 0) {
        local_68 = (ulonglong)local_58;
        *(undefined2 *)((longlong)&local_78 + (ulonglong)local_58 * 2) = 0;
      }
      else if (uVar7 < 8) {
        puVar4 = &local_78;
        local_68 = uVar7;
        for (uVar5 = uVar7; uVar5 != 0; uVar5 = uVar5 - 1) {
          *(undefined2 *)puVar4 = 0;
          puVar4 = (undefined8 *)((longlong)puVar4 + 2);
        }
        *(undefined2 *)((longlong)&local_78 + uVar7 * 2) = 0;
      }
      else {
        FUN_140013620(&local_78,uVar7,uVar10,uVar7,0);
      }
      local_50 = (undefined8 *)CONCAT44(local_50._4_4_,local_58);
      puVar4 = &local_78;
      if (7 < uStack_60) {
        puVar4 = local_78;
      }
      iVar3 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                        (*(undefined8 *)(param_1 + 0x18),param_3,param_4,puVar4);
      uVar7 = local_68;
      if (iVar3 == 0) {
        if (1 < (uint)local_50) {
          uVar5 = (ulonglong)((uint)local_50 - 1);
          if (local_68 < uVar5) {
            uVar8 = uVar5 - local_68;
            if (uStack_60 - local_68 < uVar8) {
              FUN_140013620(&local_78,uVar8,local_68,uVar8,0);
            }
            else {
              puVar4 = &local_78;
              if (7 < uStack_60) {
                puVar4 = local_78;
              }
              puVar9 = (undefined2 *)((longlong)puVar4 + local_68 * 2);
              uVar6 = uVar8;
              local_68 = uVar5;
              if (uVar8 != 0) {
                for (; uVar6 != 0; uVar6 = uVar6 - 1) {
                  *puVar9 = 0;
                  puVar9 = puVar9 + 1;
                }
              }
              *(undefined2 *)((longlong)puVar4 + (uVar7 + uVar8) * 2) = 0;
            }
          }
          else {
            puVar4 = &local_78;
            if (7 < uStack_60) {
              puVar4 = local_78;
            }
            local_68 = uVar5;
            *(undefined2 *)((longlong)puVar4 + uVar5 * 2) = 0;
          }
          *param_2 = local_78;
          param_2[1] = uStack_70;
          param_2[2] = local_68;
          param_2[3] = uStack_60;
          *(undefined1 *)(param_2 + 4) = 1;
          goto LAB_1400093e9;
        }
        *param_2 = 0;
        param_2[1] = uStack_90;
        param_2[2] = 0;
        param_2[3] = 7;
        *(undefined1 *)(param_2 + 4) = 1;
        if (uStack_60 < 8) goto LAB_1400093e9;
        if (0xfff < uStack_60 * 2 + 2) {
          lVar1 = local_78[-1];
          goto joined_r0x000140009353;
        }
      }
      else {
        *(undefined1 *)(param_2 + 4) = 0;
        if (uStack_60 < 8) goto LAB_1400093e9;
        if (0xfff < uStack_60 * 2 + 2) {
          lVar1 = local_78[-1];
joined_r0x000140009353:
          if (0x1f < (ulonglong)((longlong)local_78 + (-8 - lVar1))) {
            FUN_140035d28();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
        }
      }
      FUN_14002f180();
      goto LAB_1400093e9;
    }
  }
  uStack_60 = 7;
  local_68 = 0;
  local_78 = (undefined8 *)0x0;
  *param_2 = 0;
  param_2[1] = uStack_70;
  param_2[2] = 0;
  param_2[3] = 7;
  *(undefined1 *)(param_2 + 4) = 1;
LAB_1400093e9:
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_c8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140009410 @ 140009410

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */