void __fastcall FUN_10028cd0(undefined **param_1,void *param_2)

{
  undefined **ppuVar1;
  int *piVar2;
  undefined *puVar3;
  uint uVar4;
  int *piVar5;
  undefined4 uVar6;
  int iVar7;
  uint *puVar8;
  undefined **extraout_ECX;
  undefined **ppuVar9;
  uint *puVar10;
  uint uStack_534;
  int local_47c [6];
  undefined **local_464;
  int *local_460;
  int *local_45c;
  char local_455;
  undefined1 local_454 [1048];
  short local_3c [10];
  undefined8 local_28;
  int local_20;
  undefined **local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050798;
  local_10 = ExceptionList;
  uStack_534 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_534;
  ExceptionList = &local_10;
  local_464 = param_1;
  local_1c = param_1;
  local_18 = uStack_534;
  FUN_1000c210(local_454,L"get_system_uuid");
  local_8._0_1_ = 1;
  local_8._1_3_ = 0;
  local_28 = 0;
  piVar5 = FUN_100277f0(&local_1c,0x100613a0);
  local_8 = CONCAT31(local_8._1_3_,2);
  if ((undefined4 *)*piVar5 == (undefined4 *)0x0) {
    uVar6 = 0;
  }
  else {
    uVar6 = *(undefined4 *)*piVar5;
  }
  FUN_1002c2f0(param_2,(undefined4 *)&local_28,uVar6);
  ppuVar9 = local_1c;
  if (local_1c != (undefined **)0x0) {
    LOCK();
    ppuVar1 = local_1c + 2;
    puVar3 = *ppuVar1;
    *ppuVar1 = *ppuVar1 + -1;
    UNLOCK();
    if ((puVar3 == (undefined *)0x1) && (local_1c != (undefined **)0x0)) {
      if (*local_1c != (undefined *)0x0) {
        Ordinal_6(*local_1c);
        *ppuVar9 = (undefined *)0x0;
      }
      if (ppuVar9[1] != (undefined *)0x0) {
        thunk_FUN_100330ca(ppuVar9[1]);
        ppuVar9[1] = (undefined *)0x0;
      }
      FUN_1002e346(ppuVar9);
    }
    local_1c = (undefined **)0x0;
  }
  local_460 = (int *)0x0;
  local_45c = (int *)0x0;
  local_455 = FUN_1002bf50(&local_28,(int *)&local_460);
  local_8._0_1_ = 5;
  if (local_45c != (int *)0x0) {
    (**(code **)(*local_45c + 8))(local_45c);
  }
  local_8._0_1_ = 6;
  if (local_460 != (int *)0x0) {
    (**(code **)(*local_460 + 8))(local_460);
  }
  local_8._0_1_ = 4;
  if (local_455 != '\0') {
    *param_1 = (undefined *)0x0;
    param_1[4] = (undefined *)0x0;
    param_1[5] = (undefined *)0x7;
    *(undefined2 *)param_1 = 0;
    local_8._0_1_ = 7;
    if (local_28._4_4_ != (int *)0x0) {
      (**(code **)(*local_28._4_4_ + 8))(local_28._4_4_);
    }
    local_8 = CONCAT31(local_8._1_3_,8);
    if ((int *)local_28 != (int *)0x0) {
      (**(code **)(*(int *)local_28 + 8))((int *)local_28);
      FUN_1000c320((int)local_454);
      FUN_1002913a();
      return;
    }
    goto LAB_10028f86;
  }
  piVar5 = (int *)operator_new(0xc);
  local_8._0_1_ = 9;
  if (piVar5 == (int *)0x0) {
    piVar5 = (int *)0x0;
LAB_10028ea4:
    local_8._0_1_ = 4;
    local_45c = piVar5;
    if (piVar5 != (int *)0x0) {
      local_8._0_1_ = 10;
      local_20 = 0;
      local_1c = &PTR_vftable_10069aa8;
      FUN_1002c0e0((void *)((int)&local_28 + 4),local_3c,*piVar5,&local_20);
      iVar7 = local_20;
      ppuVar9 = local_1c;
      if ((local_1c[1] == DAT_10069aac) && (local_20 == 0)) {
        local_8._0_1_ = 0xc;
        LOCK();
        piVar2 = piVar5 + 2;
        iVar7 = *piVar2;
        *piVar2 = *piVar2 + -1;
        UNLOCK();
        if (iVar7 == 1) {
          if (*piVar5 != 0) {
            Ordinal_6(*piVar5);
            *piVar5 = 0;
          }
          if ((void *)piVar5[1] != (void *)0x0) {
            thunk_FUN_100330ca((void *)piVar5[1]);
            piVar5[1] = 0;
          }
          FUN_1002e346(piVar5);
        }
        if (local_3c[0] == 8) {
          piVar5 = (int *)FUN_10027a20(&local_1c,local_3c);
          local_8 = CONCAT31(local_8._1_3_,0xf);
          if ((undefined4 *)*piVar5 == (undefined4 *)0x0) {
            puVar10 = (uint *)0x0;
          }
          else {
            puVar10 = *(uint **)*piVar5;
          }
          *param_1 = (undefined *)0x0;
          param_1[4] = (undefined *)0x0;
          param_1[5] = (undefined *)0x7;
          *(undefined2 *)param_1 = 0;
          puVar8 = puVar10;
          do {
            uVar4 = *puVar8;
            puVar8 = (uint *)((int)puVar8 + 2);
          } while ((short)uVar4 != 0);
          FUN_10001d40(param_1,puVar10,(int)puVar8 - ((int)puVar10 + 2) >> 1);
          ppuVar9 = local_1c;
          if (local_1c != (undefined **)0x0) {
            LOCK();
            ppuVar1 = local_1c + 2;
            puVar3 = *ppuVar1;
            *ppuVar1 = *ppuVar1 + -1;
            UNLOCK();
            if ((puVar3 == (undefined *)0x1) && (local_1c != (undefined **)0x0)) {
              if (*local_1c != (undefined *)0x0) {
                Ordinal_6(*local_1c);
                *ppuVar9 = (undefined *)0x0;
              }
              if (ppuVar9[1] != (undefined *)0x0) {
                thunk_FUN_100330ca(ppuVar9[1]);
                ppuVar9[1] = (undefined *)0x0;
              }
              FUN_1002e346(ppuVar9);
            }
            local_1c = (undefined **)0x0;
          }
          Ordinal_9(local_3c);
          local_8._0_1_ = 0x10;
          if (local_28._4_4_ != (int *)0x0) {
            (**(code **)(*local_28._4_4_ + 8))(local_28._4_4_);
          }
          local_8 = CONCAT31(local_8._1_3_,0x11);
          if ((int *)local_28 != (int *)0x0) {
            (**(code **)(*(int *)local_28 + 8))((int *)local_28);
          }
          FUN_1000c320((int)local_454);
          FUN_1002913a();
          return;
        }
        *param_1 = (undefined *)0x0;
        param_1[4] = (undefined *)0x0;
        param_1[5] = (undefined *)0x7;
        *(undefined2 *)param_1 = 0;
        Ordinal_9(local_3c);
        local_8._0_1_ = 0xd;
        if (local_28._4_4_ != (int *)0x0) {
          (**(code **)(*local_28._4_4_ + 8))(local_28._4_4_);
        }
        local_8 = CONCAT31(local_8._1_3_,0xe);
        if ((int *)local_28 != (int *)0x0) {
          (**(code **)(*(int *)local_28 + 8))((int *)local_28);
        }
LAB_10028f86:
        FUN_1000c320((int)local_454);
        FUN_1002913a();
        return;
      }
      goto LAB_1002916a;
    }
  }
  else {
    *piVar5 = 0;
    piVar5[1] = 0;
    piVar5[2] = 1;
    local_45c = piVar5;
    iVar7 = Ordinal_2(L"UUID");
    *piVar5 = iVar7;
    if (iVar7 != 0) goto LAB_10028ea4;
    FUN_1002f620(0x8007000e);
  }
  iVar7 = FUN_1002f620(0x8007000e);
  ppuVar9 = extraout_ECX;
LAB_1002916a:
  FUN_10027cd0(local_47c,(uint *)0x10061648,iVar7,(int *)ppuVar9);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_47c,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: Catch@10029077 @ 10029077