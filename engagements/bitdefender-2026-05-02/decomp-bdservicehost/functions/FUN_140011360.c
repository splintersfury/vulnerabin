void FUN_140011360(undefined8 param_1,undefined4 *param_2,undefined4 *param_3,longlong param_4,
                  short param_5,byte *param_6,ulonglong param_7)

{
  char cVar1;
  int iVar2;
  short *psVar3;
  code *pcVar4;
  longlong lVar5;
  longlong lVar6;
  undefined2 uVar7;
  undefined2 uVar8;
  short sVar9;
  uint uVar10;
  ulonglong uVar11;
  undefined8 *puVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  longlong lVar15;
  short ****ppppsVar16;
  byte *pbVar17;
  char *pcVar18;
  ulonglong uVar19;
  longlong lVar20;
  short *psVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined1 auStackY_e8 [32];
  undefined4 local_b8;
  undefined4 uStack_b4;
  undefined8 uStack_b0;
  undefined4 *local_a8;
  ulonglong local_a0;
  longlong local_98;
  undefined4 *local_90;
  undefined2 local_88 [4];
  short ***local_80 [2];
  ulonglong local_70;
  ulonglong local_68;
  char local_60;
  undefined7 uStack_5f;
  undefined8 local_50;
  ulonglong local_48;
  ulonglong local_40;
  
  local_40 = DAT_14007a060 ^ (ulonglong)auStackY_e8;
  if ((param_7 == 0) || (local_a0 = 1, (*param_6 - 0x2b & 0xfd) != 0)) {
    local_a0 = 0;
  }
  if ((*(uint *)(param_4 + 0x18) & 0x3000) == 0x3000) {
    pbVar17 = &DAT_14006b4dc;
    if (((local_a0 + 2 <= param_7) && (param_6[local_a0] == 0x30)) &&
       ((param_6[local_a0 + 1] + 0xa8 & 0xdf) == 0)) {
      local_a0 = local_a0 + 2;
    }
  }
  else {
    pbVar17 = &DAT_14006b4d8;
  }
  uVar19 = local_a0;
  local_a8 = param_3;
  local_98 = param_4;
  local_90 = param_2;
  uVar11 = FUN_140039240(param_6,pbVar17);
  local_88[0] = 0x2e;
  puVar12 = (undefined8 *)FUN_140035e08();
  local_88[0] = CONCAT11(local_88[0]._1_1_,*(undefined1 *)*puVar12);
  uVar13 = FUN_140039240(param_6,(byte *)local_88);
  uStack_b0 = *(longlong *)(*(longlong *)(param_4 + 0x40) + 8);
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar14 = FUN_140013c80((longlong)&local_b8);
  if ((uStack_b0 != 0) && (lVar15 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar15 != 0))
  {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar15,1);
  }
  local_70 = 0;
  local_68 = 7;
  local_80[0] = (short ***)0x0;
  FUN_1400101a0((longlong *)local_80,param_7,0);
  ppppsVar16 = local_80;
  if (7 < local_68) {
    ppppsVar16 = (short ****)local_80[0];
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar14,param_6,param_6 + param_7,ppppsVar16);
  uStack_b0 = *(longlong *)(*(longlong *)(local_98 + 0x40) + 8);
  (*(code *)PTR__guard_dispatch_icall_14005b538)();
  uVar14 = FUN_1400134e0((longlong)&local_b8);
  if ((uStack_b0 != 0) && (lVar15 = (*(code *)PTR__guard_dispatch_icall_14005b538)(), lVar15 != 0))
  {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar15,1);
  }
  (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar14,&local_60);
  uVar7 = (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar14);
  if (uVar13 != param_7) {
    uVar8 = (*(code *)PTR__guard_dispatch_icall_14005b538)(uVar14);
    ppppsVar16 = local_80;
    if (7 < local_68) {
      ppppsVar16 = (short ****)local_80[0];
    }
    *(undefined2 *)((longlong)ppppsVar16 + uVar13 * 2) = uVar8;
  }
  if (uVar13 == param_7) {
    uVar13 = uVar11;
  }
  pcVar18 = &local_60;
  if (0xf < local_48) {
    pcVar18 = (char *)CONCAT71(uStack_5f,local_60);
  }
  cVar1 = *pcVar18;
  uVar11 = local_70;
  while (((local_70 = uVar11, cVar1 != '\x7f' && ('\0' < cVar1)) &&
         ((ulonglong)(longlong)cVar1 < uVar13 - uVar19))) {
    uVar13 = uVar13 - (longlong)cVar1;
    if (uVar11 < uVar13) goto LAB_140011ad2;
    if (local_68 == uVar11) {
      FUN_140013dc0(local_80,1,uVar11,uVar13,1,uVar7);
    }
    else {
      local_70 = uVar11 + 1;
      ppppsVar16 = local_80;
      if (7 < local_68) {
        ppppsVar16 = (short ****)local_80[0];
      }
      puVar12 = (undefined8 *)((longlong)ppppsVar16 + uVar13 * 2);
      FUN_1400316b0((undefined8 *)((longlong)puVar12 + 2),puVar12,(uVar11 - uVar13) * 2 + 2);
      *(undefined2 *)puVar12 = uVar7;
      uVar19 = local_a0;
    }
    if ('\0' < pcVar18[1]) {
      pcVar18 = pcVar18 + 1;
    }
    uVar11 = local_70;
    cVar1 = *pcVar18;
  }
  uVar13 = *(ulonglong *)(local_98 + 0x28);
  if (((longlong)uVar13 < 1) || (uVar13 <= uVar11)) {
    lVar15 = 0;
  }
  else {
    lVar15 = uVar13 - uVar11;
  }
  uVar10 = *(uint *)(local_98 + 0x18) & 0x1c0;
  if (uVar10 == 0x40) {
    ppppsVar16 = local_80;
    if (7 < local_68) {
      ppppsVar16 = (short ****)local_80[0];
    }
    local_b8 = *local_a8;
    uStack_b4 = local_a8[1];
    uStack_b0._0_4_ = (undefined4)*(longlong *)(local_a8 + 2);
    uStack_b0._4_4_ = local_a8[3];
    lVar5 = *(longlong *)(local_a8 + 2);
    lVar6 = lVar5;
    if (uVar19 != 0) {
      do {
        uStack_b0 = lVar6;
        sVar9 = *(short *)ppppsVar16;
        if (lVar5 == 0) {
LAB_1400118f3:
          local_b8 = CONCAT31(local_b8._1_3_,1);
        }
        else {
          if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_1400118d5:
            sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,sVar9);
          }
          else {
            iVar2 = **(int **)(lVar5 + 0x58);
            if (iVar2 < 1) goto LAB_1400118d5;
            **(int **)(lVar5 + 0x58) = iVar2 + -1;
            psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
            **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
            *psVar21 = sVar9;
          }
          if (sVar9 == -1) goto LAB_1400118f3;
        }
        ppppsVar16 = (short ****)((longlong)ppppsVar16 + 2);
        uVar19 = uVar19 - 1;
        lVar6 = uStack_b0;
      } while (uVar19 != 0);
LAB_140011901:
    }
  }
  else {
    local_b8 = *local_a8;
    uStack_b4 = local_a8[1];
    uStack_b0._0_4_ = (undefined4)*(longlong *)(local_a8 + 2);
    uStack_b0._4_4_ = local_a8[3];
    lVar5 = *(longlong *)(local_a8 + 2);
    if (uVar10 == 0x100) {
      ppppsVar16 = local_80;
      if (7 < local_68) {
        ppppsVar16 = (short ****)local_80[0];
      }
      lVar6 = lVar5;
      if (uVar19 != 0) {
        do {
          uStack_b0 = lVar6;
          sVar9 = *(short *)ppppsVar16;
          if (lVar5 == 0) {
LAB_1400117f6:
            local_b8 = CONCAT31(local_b8._1_3_,1);
          }
          else {
            if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_1400117d8:
              sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,sVar9);
            }
            else {
              iVar2 = **(int **)(lVar5 + 0x58);
              if (iVar2 < 1) goto LAB_1400117d8;
              **(int **)(lVar5 + 0x58) = iVar2 + -1;
              psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
              **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
              *psVar21 = sVar9;
            }
            if (sVar9 == -1) goto LAB_1400117f6;
          }
          ppppsVar16 = (short ****)((longlong)ppppsVar16 + 2);
          uVar19 = uVar19 - 1;
          lVar6 = uStack_b0;
        } while (uVar19 != 0);
      }
      lVar5 = uStack_b0;
      if (lVar15 != 0) {
        do {
          if (lVar5 == 0) {
LAB_140011863:
            local_b8 = CONCAT31(local_b8._1_3_,1);
          }
          else {
            if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_14001184a:
              sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,param_5);
            }
            else {
              iVar2 = **(int **)(lVar5 + 0x58);
              if (iVar2 < 1) goto LAB_14001184a;
              **(int **)(lVar5 + 0x58) = iVar2 + -1;
              psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
              **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
              *psVar21 = param_5;
              sVar9 = param_5;
            }
            if (sVar9 == -1) goto LAB_140011863;
          }
          lVar15 = lVar15 + -1;
        } while (lVar15 != 0);
      }
      lVar15 = 0;
    }
    else {
      lVar6 = lVar5;
      if (lVar15 != 0) {
        do {
          uStack_b0 = lVar6;
          if (lVar5 == 0) {
LAB_1400116ee:
            local_b8 = CONCAT31(local_b8._1_3_,1);
          }
          else {
            if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_1400116d5:
              sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,param_5);
            }
            else {
              iVar2 = **(int **)(lVar5 + 0x58);
              if (iVar2 < 1) goto LAB_1400116d5;
              **(int **)(lVar5 + 0x58) = iVar2 + -1;
              psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
              **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
              *psVar21 = param_5;
              sVar9 = param_5;
            }
            if (sVar9 == -1) goto LAB_1400116ee;
          }
          lVar15 = lVar15 + -1;
          lVar6 = uStack_b0;
        } while (lVar15 != 0);
      }
      lVar15 = 0;
      ppppsVar16 = local_80;
      if (7 < local_68) {
        ppppsVar16 = (short ****)local_80[0];
      }
      lVar5 = uStack_b0;
      uVar13 = local_a0;
      if (local_a0 != 0) {
        do {
          sVar9 = *(short *)ppppsVar16;
          if (lVar5 == 0) {
LAB_140011776:
            local_b8 = CONCAT31(local_b8._1_3_,1);
          }
          else {
            if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_140011758:
              sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,sVar9);
            }
            else {
              iVar2 = **(int **)(lVar5 + 0x58);
              if (iVar2 < 1) goto LAB_140011758;
              **(int **)(lVar5 + 0x58) = iVar2 + -1;
              psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
              **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
              *psVar21 = sVar9;
            }
            if (sVar9 == -1) goto LAB_140011776;
          }
          ppppsVar16 = (short ****)((longlong)ppppsVar16 + 2);
          uVar13 = uVar13 - 1;
        } while (uVar13 != 0);
        goto LAB_140011901;
      }
    }
  }
  *local_a8 = local_b8;
  local_a8[1] = uStack_b4;
  local_a8[2] = (undefined4)uStack_b0;
  local_a8[3] = uStack_b0._4_4_;
  ppppsVar16 = local_80;
  if (7 < local_68) {
    ppppsVar16 = (short ****)local_80[0];
  }
  psVar21 = (short *)((longlong)ppppsVar16 + local_a0 * 2);
  local_b8 = *local_a8;
  uStack_b4 = local_a8[1];
  uStack_b0._0_4_ = (undefined4)*(longlong *)(local_a8 + 2);
  uStack_b0._4_4_ = local_a8[3];
  lVar5 = *(longlong *)(local_a8 + 2);
  lVar20 = uVar11 - local_a0;
  lVar6 = lVar5;
  if (lVar20 != 0) {
    do {
      uStack_b0 = lVar6;
      sVar9 = *psVar21;
      if (lVar5 == 0) {
LAB_140011989:
        local_b8 = CONCAT31(local_b8._1_3_,1);
      }
      else {
        if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_14001196b:
          sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,sVar9);
        }
        else {
          iVar2 = **(int **)(lVar5 + 0x58);
          if (iVar2 < 1) goto LAB_14001196b;
          **(int **)(lVar5 + 0x58) = iVar2 + -1;
          psVar3 = (short *)**(longlong **)(lVar5 + 0x40);
          **(longlong **)(lVar5 + 0x40) = (longlong)(psVar3 + 1);
          *psVar3 = sVar9;
        }
        if (sVar9 == -1) goto LAB_140011989;
      }
      psVar21 = psVar21 + 1;
      lVar20 = lVar20 + -1;
      lVar6 = uStack_b0;
    } while (lVar20 != 0);
  }
  *(undefined8 *)(local_98 + 0x28) = 0;
  lVar5 = uStack_b0;
  uVar22 = (undefined4)uStack_b0;
  uVar23 = uStack_b0._4_4_;
  if (lVar15 != 0) {
    do {
      if (lVar5 == 0) {
LAB_140011a02:
        local_b8 = CONCAT31(local_b8._1_3_,1);
      }
      else {
        if (**(longlong **)(lVar5 + 0x40) == 0) {
LAB_1400119e9:
          sVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,param_5);
        }
        else {
          iVar2 = **(int **)(lVar5 + 0x58);
          if (iVar2 < 1) goto LAB_1400119e9;
          **(int **)(lVar5 + 0x58) = iVar2 + -1;
          psVar21 = (short *)**(longlong **)(lVar5 + 0x40);
          **(longlong **)(lVar5 + 0x40) = (longlong)(psVar21 + 1);
          *psVar21 = param_5;
          sVar9 = param_5;
        }
        if (sVar9 == -1) goto LAB_140011a02;
      }
      lVar15 = lVar15 + -1;
    } while (lVar15 != 0);
    uVar22 = (undefined4)uStack_b0;
    uVar23 = uStack_b0._4_4_;
  }
  *local_90 = local_b8;
  local_90[1] = uStack_b4;
  local_90[2] = uVar22;
  local_90[3] = uVar23;
  if (0xf < local_48) {
    if ((0xfff < local_48 + 1) &&
       (0x1f < (CONCAT71(uStack_5f,local_60) - *(longlong *)(CONCAT71(uStack_5f,local_60) + -8)) -
               8U)) goto LAB_140011ad8;
    FUN_14002f180();
  }
  local_50 = 0;
  local_48 = 0xf;
  local_60 = '\0';
  if (7 < local_68) {
    if ((0xfff < local_68 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_80[0] + (-8 - (longlong)local_80[0][-1])))) {
      FUN_140035d28();
LAB_140011ad2:
      FUN_140011df0();
LAB_140011ad8:
      FUN_140035d28();
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    FUN_14002f180();
  }
  FUN_14002f160(local_40 ^ (ulonglong)auStackY_e8);
  return;
}


// FUNCTION_END

// FUNCTION_START: ~_Sentry_base @ 140011ae0

/* Library Function - Multiple Matches With Same Base Name
    public: __cdecl std::basic_ostream<char,struct std::char_traits<char>
   >::_Sentry_base::~_Sentry_base(void) __ptr64
    public: __cdecl std::basic_ostream<unsigned short,struct std::char_traits<unsigned short>
   >::_Sentry_base::~_Sentry_base(void) __ptr64
    public: __cdecl std::basic_ostream<wchar_t,struct std::char_traits<wchar_t>
   >::_Sentry_base::~_Sentry_base(void) __ptr64
   
   Library: Visual Studio 2019 Release */

void ~_Sentry_base(longlong *param_1)

{
  if (*(longlong *)((longlong)*(int *)(*(longlong *)*param_1 + 4) + 0x48 + *param_1) != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011b10 @ 140011b10