void FUN_140010c50(undefined8 param_1,undefined4 *param_2,undefined4 *param_3,longlong param_4,
                  short param_5,char *param_6,ulonglong param_7)

{
  undefined8 *puVar1;
  char cVar2;
  int iVar3;
  ulonglong uVar4;
  short *psVar5;
  code *pcVar6;
  longlong lVar7;
  ulonglong uVar8;
  undefined2 uVar9;
  short sVar10;
  uint uVar11;
  undefined8 uVar12;
  longlong lVar13;
  short ****ppppsVar14;
  char *pcVar15;
  ulonglong uVar16;
  longlong lVar17;
  short *psVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined1 auStackY_e8 [32];
  undefined4 local_b8;
  undefined4 uStack_b4;
  undefined8 uStack_b0;
  ulonglong local_a8;
  undefined4 *local_a0;
  longlong local_98;
  undefined4 *local_90;
  short ***local_88 [2];
  ulonglong local_78;
  ulonglong local_70;
  char local_68;
  undefined7 uStack_67;
  undefined8 local_58;
  ulonglong local_50;
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_e8;
  if ((param_7 == 0) || (local_a8 = 1, (*param_6 - 0x2bU & 0xfd) != 0)) {
    local_a8 = 0;
  }
  if (((((*(uint *)(param_4 + 0x18) & 0xe00) == 0x800) && (local_a8 + 2 <= param_7)) &&
      (param_6[local_a8] == '0')) && ((param_6[local_a8 + 1] + 0xa8U & 0xdf) == 0)) {
    local_a8 = local_a8 + 2;
  }
  uVar16 = local_a8;
  uStack_b0 = *(longlong *)(*(longlong *)(param_4 + 0x40) + 8);
  local_a0 = param_3;
  local_98 = param_4;
  local_90 = param_2;
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar12 = FUN_140013c80((longlong)&local_b8);
  if ((uStack_b0 != 0) && (lVar13 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar13 != 0))
  {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar13,1);
  }
  local_78 = 0;
  local_70 = 7;
  local_88[0] = (short ***)0x0;
  FUN_1400101a0((longlong *)local_88,param_7,0);
  ppppsVar14 = local_88;
  if (7 < local_70) {
    ppppsVar14 = (short ****)local_88[0];
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar12,param_6,param_6 + param_7,ppppsVar14);
  uStack_b0 = *(longlong *)(*(longlong *)(param_4 + 0x40) + 8);
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar12 = FUN_1400134e0((longlong)&local_b8);
  if ((uStack_b0 != 0) && (lVar13 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar13 != 0))
  {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar13,1);
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar12,&local_68);
  pcVar15 = &local_68;
  if (0xf < local_50) {
    pcVar15 = (char *)CONCAT71(uStack_67,local_68);
  }
  if ((byte)(*pcVar15 - 1U) < 0x7e) {
    uVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar12);
    cVar2 = *pcVar15;
    while (((cVar2 != '\x7f' && ('\0' < cVar2)) && ((ulonglong)(longlong)cVar2 < param_7 - uVar16)))
    {
      param_7 = param_7 - (longlong)cVar2;
      if (local_78 < param_7) goto LAB_14001134e;
      if (local_70 == local_78) {
        FUN_140013dc0(local_88,1,local_78,param_7,1,uVar9);
      }
      else {
        ppppsVar14 = local_88;
        if (7 < local_70) {
          ppppsVar14 = (short ****)local_88[0];
        }
        puVar1 = (undefined8 *)((longlong)ppppsVar14 + param_7 * 2);
        lVar13 = local_78 - param_7;
        local_78 = local_78 + 1;
        FUN_1400316b0((undefined8 *)((longlong)puVar1 + 2),puVar1,lVar13 * 2 + 2);
        *(undefined2 *)puVar1 = uVar9;
        uVar16 = local_a8;
      }
      if ('\0' < pcVar15[1]) {
        pcVar15 = pcVar15 + 1;
      }
      cVar2 = *pcVar15;
    }
  }
  uVar8 = local_78;
  uVar4 = *(ulonglong *)(local_98 + 0x28);
  if (((longlong)uVar4 < 1) || (uVar4 <= local_78)) {
    lVar13 = 0;
  }
  else {
    lVar13 = uVar4 - local_78;
  }
  uVar11 = *(uint *)(local_98 + 0x18) & 0x1c0;
  local_b8 = *param_3;
  uStack_b4 = param_3[1];
  uStack_b0._0_4_ = (undefined4)*(longlong *)(param_3 + 2);
  uStack_b0._4_4_ = param_3[3];
  lVar7 = *(longlong *)(param_3 + 2);
  if (uVar11 == 0x40) {
    ppppsVar14 = local_88;
    if (7 < local_70) {
      ppppsVar14 = (short ****)local_88[0];
    }
    lVar17 = lVar7;
    if (uVar16 != 0) {
      do {
        uStack_b0 = lVar17;
        sVar10 = *(short *)ppppsVar14;
        if (lVar7 == 0) {
LAB_140011173:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140011155:
            sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar10);
          }
          else {
            iVar3 = **(int **)(lVar7 + 0x58);
            if (iVar3 < 1) goto LAB_140011155;
            **(int **)(lVar7 + 0x58) = iVar3 + -1;
            psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
            **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
            *psVar18 = sVar10;
          }
          if (sVar10 == -1) goto LAB_140011173;
        }
        ppppsVar14 = (short ****)((longlong)ppppsVar14 + 2);
        uVar16 = uVar16 - 1;
        lVar17 = uStack_b0;
      } while (uVar16 != 0);
LAB_140011181:
    }
  }
  else if (uVar11 == 0x100) {
    ppppsVar14 = local_88;
    if (7 < local_70) {
      ppppsVar14 = (short ****)local_88[0];
    }
    lVar17 = lVar7;
    if (uVar16 != 0) {
      do {
        uStack_b0 = lVar17;
        sVar10 = *(short *)ppppsVar14;
        if (lVar7 == 0) {
LAB_140011083:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140011065:
            sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar10);
          }
          else {
            iVar3 = **(int **)(lVar7 + 0x58);
            if (iVar3 < 1) goto LAB_140011065;
            **(int **)(lVar7 + 0x58) = iVar3 + -1;
            psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
            **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
            *psVar18 = sVar10;
          }
          if (sVar10 == -1) goto LAB_140011083;
        }
        ppppsVar14 = (short ****)((longlong)ppppsVar14 + 2);
        uVar16 = uVar16 - 1;
        lVar17 = uStack_b0;
      } while (uVar16 != 0);
    }
    lVar7 = uStack_b0;
    if (lVar13 != 0) {
      do {
        if (lVar7 == 0) {
LAB_1400110f0:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_1400110d7:
            sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,param_5);
          }
          else {
            iVar3 = **(int **)(lVar7 + 0x58);
            if (iVar3 < 1) goto LAB_1400110d7;
            **(int **)(lVar7 + 0x58) = iVar3 + -1;
            psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
            **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
            *psVar18 = param_5;
            sVar10 = param_5;
          }
          if (sVar10 == -1) goto LAB_1400110f0;
        }
        lVar13 = lVar13 + -1;
      } while (lVar13 != 0);
    }
    lVar13 = 0;
  }
  else {
    lVar17 = lVar7;
    if (lVar13 != 0) {
      do {
        uStack_b0 = lVar17;
        if (lVar7 == 0) {
LAB_140010f72:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140010f59:
            sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,param_5);
          }
          else {
            iVar3 = **(int **)(lVar7 + 0x58);
            if (iVar3 < 1) goto LAB_140010f59;
            **(int **)(lVar7 + 0x58) = iVar3 + -1;
            psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
            **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
            *psVar18 = param_5;
            sVar10 = param_5;
          }
          if (sVar10 == -1) goto LAB_140010f72;
        }
        lVar13 = lVar13 + -1;
        lVar17 = uStack_b0;
      } while (lVar13 != 0);
    }
    lVar13 = 0;
    ppppsVar14 = local_88;
    if (7 < local_70) {
      ppppsVar14 = (short ****)local_88[0];
    }
    lVar7 = uStack_b0;
    uVar16 = local_a8;
    if (local_a8 != 0) {
      do {
        sVar10 = *(short *)ppppsVar14;
        if (lVar7 == 0) {
LAB_140011002:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140010fe4:
            sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar10);
          }
          else {
            iVar3 = **(int **)(lVar7 + 0x58);
            if (iVar3 < 1) goto LAB_140010fe4;
            **(int **)(lVar7 + 0x58) = iVar3 + -1;
            psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
            **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
            *psVar18 = sVar10;
          }
          if (sVar10 == -1) goto LAB_140011002;
        }
        ppppsVar14 = (short ****)((longlong)ppppsVar14 + 2);
        uVar16 = uVar16 - 1;
      } while (uVar16 != 0);
      goto LAB_140011181;
    }
  }
  *local_a0 = local_b8;
  local_a0[1] = uStack_b4;
  local_a0[2] = (undefined4)uStack_b0;
  local_a0[3] = uStack_b0._4_4_;
  ppppsVar14 = local_88;
  if (7 < local_70) {
    ppppsVar14 = (short ****)local_88[0];
  }
  psVar18 = (short *)((longlong)ppppsVar14 + local_a8 * 2);
  lVar7 = uStack_b0;
  lVar17 = uVar8 - local_a8;
  if (lVar17 != 0) {
    do {
      sVar10 = *psVar18;
      if (lVar7 == 0) {
LAB_140011203:
        local_b8 = CONCAT31(local_b8._1_3_,1);
      }
      else {
        if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_1400111e5:
          sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,sVar10);
        }
        else {
          iVar3 = **(int **)(lVar7 + 0x58);
          if (iVar3 < 1) goto LAB_1400111e5;
          **(int **)(lVar7 + 0x58) = iVar3 + -1;
          psVar5 = (short *)**(longlong **)(lVar7 + 0x40);
          **(longlong **)(lVar7 + 0x40) = (longlong)(psVar5 + 1);
          *psVar5 = sVar10;
        }
        if (sVar10 == -1) goto LAB_140011203;
      }
      psVar18 = psVar18 + 1;
      lVar17 = lVar17 + -1;
    } while (lVar17 != 0);
  }
  *(undefined8 *)(local_98 + 0x28) = 0;
  lVar7 = uStack_b0;
  uVar19 = (undefined4)uStack_b0;
  uVar20 = uStack_b0._4_4_;
  if (lVar13 != 0) {
    do {
      if (lVar7 == 0) {
LAB_14001127e:
        local_b8 = CONCAT31(local_b8._1_3_,1);
      }
      else {
        if (**(longlong **)(lVar7 + 0x40) == 0) {
LAB_140011265:
          sVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,param_5);
        }
        else {
          iVar3 = **(int **)(lVar7 + 0x58);
          if (iVar3 < 1) goto LAB_140011265;
          **(int **)(lVar7 + 0x58) = iVar3 + -1;
          psVar18 = (short *)**(longlong **)(lVar7 + 0x40);
          **(longlong **)(lVar7 + 0x40) = (longlong)(psVar18 + 1);
          *psVar18 = param_5;
          sVar10 = param_5;
        }
        if (sVar10 == -1) goto LAB_14001127e;
      }
      lVar13 = lVar13 + -1;
    } while (lVar13 != 0);
    uVar19 = (undefined4)uStack_b0;
    uVar20 = uStack_b0._4_4_;
  }
  *local_90 = local_b8;
  local_90[1] = uStack_b4;
  local_90[2] = uVar19;
  local_90[3] = uVar20;
  if (0xf < local_50) {
    if ((0xfff < local_50 + 1) &&
       (0x1f < (CONCAT71(uStack_67,local_68) - *(longlong *)(CONCAT71(uStack_67,local_68) + -8)) -
               8U)) goto LAB_140011354;
    FUN_14002f180();
  }
  local_58 = 0;
  local_50 = 0xf;
  local_68 = '\0';
  if (7 < local_70) {
    if ((0xfff < local_70 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_88[0] + (-8 - (longlong)local_88[0][-1])))) {
      FUN_140035d28();
LAB_14001134e:
      FUN_140011df0();
LAB_140011354:
      FUN_140035d28();
      pcVar6 = (code *)swi(3);
      (*pcVar6)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_e8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011360 @ 140011360