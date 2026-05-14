void FUN_14000fb50(longlong *param_1,undefined4 *param_2,undefined4 *param_3,longlong param_4,
                  short param_5,byte param_6)

{
  int iVar1;
  ulonglong uVar2;
  short *psVar3;
  code *pcVar4;
  short ***pppsVar5;
  longlong lVar6;
  longlong lVar7;
  short sVar8;
  undefined8 uVar9;
  longlong lVar10;
  short ****ppppsVar11;
  longlong lVar12;
  ulonglong uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined1 auStack_e8 [32];
  short local_c8;
  uint local_c0;
  undefined8 local_a8;
  undefined8 uStack_a0;
  ulonglong local_90;
  longlong local_88;
  undefined4 *local_80;
  short ***local_78 [2];
  ulonglong local_68;
  ulonglong local_60;
  ulonglong local_58;
  
  local_58 = DAT_14007a060 ^ (ulonglong)auStack_e8;
  local_88 = param_4;
  local_80 = param_2;
  if ((*(uint *)(param_4 + 0x18) & 0x4000) == 0) {
    local_a8._0_4_ = *param_3;
    local_a8._4_4_ = param_3[1];
    uStack_a0 = *(longlong *)(param_3 + 2);
    local_c0 = (uint)param_6;
    local_c8 = param_5;
    (*(code *)PTR__guard_dispatch_icall_14005b538)((undefined4)local_a8,param_2,&local_a8);
    goto LAB_14000fedf;
  }
  uStack_a0 = *(longlong *)(*(longlong *)(param_4 + 0x40) + 8);
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar9 = FUN_1400134e0((longlong)&local_a8);
  if ((uStack_a0 != 0) && (lVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar10 != 0))
  {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar10,1);
  }
  lVar10 = 0;
  local_68 = 0;
  local_60 = 7;
  local_78[0] = (short ***)0x0;
  if (param_6 == 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar9,&local_a8);
    FUN_14000e6b0((longlong *)local_78,&local_a8);
    if (7 < local_90) {
      if ((0xfff < local_90 * 2 + 2) &&
         (0x1f < (CONCAT44(local_a8._4_4_,(undefined4)local_a8) -
                 *(longlong *)(CONCAT44(local_a8._4_4_,(undefined4)local_a8) + -8)) - 8U))
      goto LAB_14000ff0e;
LAB_14000fcf2:
      FUN_14002f180();
    }
LAB_14000fcf7:
    uVar13 = local_68;
    uVar2 = *(ulonglong *)(param_4 + 0x28);
    lVar12 = lVar10;
    if ((0 < (longlong)uVar2) && (local_68 < uVar2)) {
      lVar12 = uVar2 - local_68;
    }
    if ((*(uint *)(param_4 + 0x18) & 0x1c0) != 0x40) {
      local_a8._0_4_ = *param_3;
      local_a8._4_4_ = param_3[1];
      uStack_a0._0_4_ = (undefined4)*(longlong *)(param_3 + 2);
      uStack_a0._4_4_ = param_3[3];
      lVar6 = *(longlong *)(param_3 + 2);
      lVar7 = lVar6;
      if (lVar12 != 0) {
        do {
          uStack_a0 = lVar7;
          if (lVar6 == 0) {
LAB_14000fd83:
            local_a8._0_4_ = CONCAT31(local_a8._1_3_,1);
          }
          else {
            if (**(longlong **)(lVar6 + 0x40) == 0) {
LAB_14000fd6a:
              sVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar6,param_5);
            }
            else {
              iVar1 = **(int **)(lVar6 + 0x58);
              if (iVar1 < 1) goto LAB_14000fd6a;
              **(int **)(lVar6 + 0x58) = iVar1 + -1;
              psVar3 = (short *)**(longlong **)(lVar6 + 0x40);
              **(longlong **)(lVar6 + 0x40) = (longlong)(psVar3 + 1);
              *psVar3 = param_5;
              sVar8 = param_5;
            }
            if (sVar8 == -1) goto LAB_14000fd83;
          }
          lVar12 = lVar12 + -1;
          lVar7 = uStack_a0;
        } while (lVar12 != 0);
      }
      *param_3 = (undefined4)local_a8;
      param_3[1] = local_a8._4_4_;
      param_3[2] = (undefined4)uStack_a0;
      param_3[3] = uStack_a0._4_4_;
      lVar12 = lVar10;
    }
    pppsVar5 = local_78[0];
    ppppsVar11 = local_78;
    if (7 < local_60) {
      ppppsVar11 = (short ****)local_78[0];
    }
    local_a8._0_4_ = *param_3;
    local_a8._4_4_ = param_3[1];
    uStack_a0._0_4_ = (undefined4)*(longlong *)(param_3 + 2);
    uStack_a0._4_4_ = param_3[3];
    lVar10 = *(longlong *)(param_3 + 2);
    lVar6 = lVar10;
    if (uVar13 != 0) {
      do {
        uStack_a0 = lVar6;
        sVar8 = *(short *)ppppsVar11;
        if (lVar10 == 0) {
LAB_14000fe15:
          local_a8._0_4_ = CONCAT31(local_a8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar10 + 0x40) == 0) {
LAB_14000fdf7:
            sVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar10,sVar8);
          }
          else {
            iVar1 = **(int **)(lVar10 + 0x58);
            if (iVar1 < 1) goto LAB_14000fdf7;
            **(int **)(lVar10 + 0x58) = iVar1 + -1;
            psVar3 = (short *)**(longlong **)(lVar10 + 0x40);
            **(longlong **)(lVar10 + 0x40) = (longlong)(psVar3 + 1);
            *psVar3 = sVar8;
          }
          if (sVar8 == -1) goto LAB_14000fe15;
        }
        ppppsVar11 = (short ****)((longlong)ppppsVar11 + 2);
        uVar13 = uVar13 - 1;
        lVar6 = uStack_a0;
      } while (uVar13 != 0);
    }
    *(undefined8 *)(local_88 + 0x28) = 0;
    lVar10 = uStack_a0;
    uVar14 = (undefined4)uStack_a0;
    uVar15 = uStack_a0._4_4_;
    if (lVar12 != 0) {
      do {
        if (lVar10 == 0) {
LAB_14000fe8f:
          local_a8._0_4_ = CONCAT31(local_a8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar10 + 0x40) == 0) {
LAB_14000fe75:
            sVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar10,param_5);
          }
          else {
            iVar1 = **(int **)(lVar10 + 0x58);
            if (iVar1 < 1) goto LAB_14000fe75;
            **(int **)(lVar10 + 0x58) = iVar1 + -1;
            psVar3 = (short *)**(longlong **)(lVar10 + 0x40);
            **(longlong **)(lVar10 + 0x40) = (longlong)(psVar3 + 1);
            *psVar3 = param_5;
            sVar8 = param_5;
          }
          if (sVar8 == -1) goto LAB_14000fe8f;
        }
        lVar12 = lVar12 + -1;
      } while (lVar12 != 0);
      uVar14 = (undefined4)uStack_a0;
      uVar15 = uStack_a0._4_4_;
    }
    *local_80 = (undefined4)local_a8;
    local_80[1] = local_a8._4_4_;
    local_80[2] = uVar14;
    local_80[3] = uVar15;
    if (local_60 < 8) {
LAB_14000fedf:
      FUN_14002f160(local_58 ^ (ulonglong)auStack_e8);
      return;
    }
    if ((local_60 * 2 + 2 < 0x1000) ||
       ((ulonglong)((longlong)pppsVar5 + (-8 - (longlong)pppsVar5[-1])) < 0x20)) {
      FUN_14002f180();
      goto LAB_14000fedf;
    }
    FUN_140035d28();
  }
  else {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    FUN_14000e6b0((longlong *)local_78,&local_a8);
    if (local_90 < 8) goto LAB_14000fcf7;
    if ((local_90 * 2 + 2 < 0x1000) ||
       ((CONCAT44(local_a8._4_4_,(undefined4)local_a8) -
        *(longlong *)(CONCAT44(local_a8._4_4_,(undefined4)local_a8) + -8)) - 8U < 0x20))
    goto LAB_14000fcf2;
  }
  FUN_140035d28();
LAB_14000ff0e:
  FUN_140035d28();
  pcVar4 = (code *)swi(3);
  (*pcVar4)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ff20 @ 14000ff20