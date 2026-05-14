void __fastcall FUN_100291a0(int *param_1,uint *param_2,wchar_t *param_3)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  undefined4 ****ppppuVar4;
  undefined4 uVar5;
  int iVar6;
  undefined **extraout_ECX;
  undefined **ppuVar7;
  int *piVar8;
  int *piVar9;
  int *piVar10;
  uint uStack_560;
  int local_550 [24];
  undefined **local_4f0 [18];
  int local_4a8 [6];
  wchar_t *local_490;
  code *local_48c;
  int *local_488;
  code *local_484;
  int *local_480;
  int *local_47c;
  int *local_478;
  char local_471;
  undefined1 local_470 [1052];
  undefined4 ***local_54 [4];
  undefined4 local_44;
  uint local_40;
  int local_3c;
  undefined **local_38;
  undefined8 local_34;
  undefined8 local_2c;
  undefined8 local_24;
  uint local_1c;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100508c8;
  local_10 = ExceptionList;
  uStack_560 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_560;
  ExceptionList = &local_10;
  piVar8 = (int *)0x0;
  local_490 = param_3;
  local_47c = (int *)0x0;
  local_480 = param_1;
  local_1c = uStack_560;
  FUN_1000c210(local_470,L"search_logicaldisks");
  local_8 = 0;
  piVar3 = FUN_100034b0(local_550,0x10,0x10061414);
  local_8._0_1_ = 1;
  if (((char)piVar3[0x12] != '\0') && (FUN_100082c0(piVar3,L"devid="), (char)piVar3[0x12] != '\0'))
  {
    FUN_100082c0(piVar3,(short *)param_2);
  }
  FUN_10003240((int)local_4f0);
  local_8._0_1_ = 2;
  local_4f0[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_4f0);
  local_8._0_1_ = 0;
  FUN_10027ff0(local_54,param_2);
  local_8._0_1_ = 4;
  ppppuVar4 = local_54;
  if (7 < local_40) {
    ppppuVar4 = (undefined4 ****)local_54[0];
  }
  local_34 = 0;
  piVar3 = FUN_100277f0(&local_47c,(int)ppppuVar4);
  local_8 = CONCAT31(local_8._1_3_,5);
  if ((undefined4 *)*piVar3 == (undefined4 *)0x0) {
    uVar5 = 0;
  }
  else {
    uVar5 = *(undefined4 *)*piVar3;
  }
  FUN_1002c2f0(local_480,(undefined4 *)&local_34,uVar5);
  piVar3 = local_47c;
  if (local_47c != (int *)0x0) {
    LOCK();
    piVar10 = local_47c + 2;
    iVar6 = *piVar10;
    *piVar10 = *piVar10 + -1;
    UNLOCK();
    if ((iVar6 == 1) && (local_47c != (int *)0x0)) {
      if (*local_47c == 0) {
        local_484 = Ordinal_6_exref;
      }
      else {
        local_484 = Ordinal_6_exref;
        Ordinal_6(*local_47c);
        *piVar3 = 0;
      }
      if ((void *)piVar3[1] != (void *)0x0) {
        thunk_FUN_100330ca((void *)piVar3[1]);
        piVar3[1] = 0;
      }
      FUN_1002e346(piVar3);
      goto LAB_10029325;
    }
  }
  local_484 = Ordinal_6_exref;
LAB_10029325:
  piVar3 = (int *)local_34;
  local_24 = 0;
  local_8._0_1_ = 8;
  if ((int *)local_34 != (int *)0x0) {
    (**(code **)(*(int *)local_34 + 4))((int *)local_34);
  }
  piVar10 = local_34._4_4_;
  local_8._0_1_ = 9;
  if (local_34._4_4_ != (int *)0x0) {
    (**(code **)(*local_34._4_4_ + 4))(local_34._4_4_);
  }
  local_24 = CONCAT44(piVar10,piVar3);
  local_2c = 0;
  local_8._0_1_ = 0xd;
  local_48c = Ordinal_2_exref;
  piVar3 = local_488;
  do {
    piVar10 = local_478;
    cVar2 = FUN_1002bf50(&local_24,(int *)&local_2c);
    if (cVar2 != '\0') {
      local_8._0_1_ = 0x1c;
      if (local_2c._4_4_ != (int *)0x0) {
        (**(code **)(*local_2c._4_4_ + 8))(local_2c._4_4_);
      }
      local_8._0_1_ = 0x1d;
      if ((int *)local_2c != (int *)0x0) {
        (**(code **)(*(int *)local_2c + 8))((int *)local_2c);
      }
      local_8._0_1_ = 0x1e;
      if (local_24._4_4_ != (int *)0x0) {
        (**(code **)(*local_24._4_4_ + 8))(local_24._4_4_);
      }
      local_8._0_1_ = 0x1f;
      if ((int *)local_24 != (int *)0x0) {
        (**(code **)(*(int *)local_24 + 8))((int *)local_24);
      }
      local_8._0_1_ = 0x20;
      if (local_34._4_4_ != (int *)0x0) {
        (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
      }
      local_8 = CONCAT31(local_8._1_3_,0x21);
      if ((int *)local_34 != (int *)0x0) {
        (**(code **)(*(int *)local_34 + 8))((int *)local_34);
      }
      if (local_40 < 8) {
LAB_10029871:
        local_44 = 0;
        local_40 = 7;
        local_54[0] = (undefined4 ***)((uint)local_54[0] & 0xffff0000);
        FUN_100298fe();
        return;
      }
      ppppuVar4 = (undefined4 ****)local_54[0];
      if ((local_40 * 2 + 2 < 0x1000) ||
         (ppppuVar4 = (undefined4 ****)local_54[0][-1],
         (uint)((int)local_54[0] + (-4 - (int)ppppuVar4)) < 0x20)) {
        FUN_1002e346(ppppuVar4);
        goto LAB_10029871;
      }
      goto LAB_10029989;
    }
    local_47c = (int *)operator_new(0xc);
    local_8._0_1_ = 0xe;
    if (local_47c != (int *)0x0) {
      *local_47c = 0;
      local_47c[1] = 0;
      local_47c[2] = 1;
      local_480 = local_47c;
      iVar6 = (*local_48c)(L"DeviceID");
      *local_480 = iVar6;
      if (iVar6 != 0) goto LAB_100293f5;
      FUN_1002f620(0x8007000e);
LAB_10029931:
      FUN_1002f620(0x8007000e);
LAB_1002993b:
      FUN_1002f620(0x8007000e);
LAB_10029945:
      FUN_1002f620(0x8007000e);
LAB_1002994f:
      FUN_1002f620(0x8007000e);
LAB_10029959:
      iVar6 = FUN_1002f620(0x8007000e);
      ppuVar7 = extraout_ECX;
LAB_10029963:
      FUN_10027cd0(local_4a8,(uint *)"objects_iterator::increment failed",iVar6,(int *)ppuVar7);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_4a8,&DAT_10067674);
    }
    local_480 = (int *)0x0;
LAB_100293f5:
    local_8._0_1_ = 0xd;
    if (local_480 == (int *)0x0) goto LAB_10029931;
    local_8 = CONCAT31(local_8._1_3_,0xf);
    piVar9 = (int *)((uint)piVar8 | 1);
    local_47c = piVar9;
    cVar2 = FUN_10029990((void *)((int)&local_24 + 4),(int *)&local_480,local_490);
    if (cVar2 == '\0') {
      piVar3 = (int *)operator_new(0xc);
      local_8._0_1_ = 0x10;
      local_8._1_3_ = 0;
      if (piVar3 != (int *)0x0) {
        *piVar3 = 0;
        piVar3[1] = 0;
        piVar3[2] = 1;
        local_488 = piVar3;
        iVar6 = (*local_48c)(L"Name");
        *piVar3 = iVar6;
        if (iVar6 != 0) goto LAB_1002947c;
        goto LAB_1002993b;
      }
      piVar3 = (int *)0x0;
LAB_1002947c:
      local_8._0_1_ = 0xf;
      local_488 = piVar3;
      if (piVar3 == (int *)0x0) goto LAB_10029945;
      local_8 = 0x11;
      piVar9 = (int *)((uint)piVar8 | 3);
      local_47c = piVar9;
      cVar2 = FUN_10029990((void *)((int)&local_24 + 4),(int *)&local_488,local_490);
      piVar3 = local_488;
      if (cVar2 != '\0') goto LAB_10029562;
      piVar8 = (int *)operator_new(0xc);
      local_8._0_1_ = 0x12;
      local_8._1_3_ = 0;
      if (piVar8 != (int *)0x0) {
        *piVar8 = 0;
        piVar8[1] = 0;
        piVar8[2] = 1;
        local_478 = piVar8;
        iVar6 = (*local_48c)(L"Caption");
        *piVar8 = iVar6;
        if (iVar6 != 0) goto LAB_10029506;
        goto LAB_1002994f;
      }
      piVar8 = (int *)0x0;
LAB_10029506:
      local_8._0_1_ = 0x11;
      local_478 = piVar8;
      if (piVar8 != (int *)0x0) {
        local_8 = 0x13;
        piVar9 = (int *)0x7;
        local_47c = (int *)0x7;
        cVar2 = FUN_10029990((void *)((int)&local_24 + 4),(int *)&local_478,local_490);
        piVar3 = local_488;
        piVar10 = local_478;
        if (cVar2 != '\0') goto LAB_10029562;
        local_471 = '\0';
        goto LAB_10029569;
      }
      goto LAB_10029959;
    }
LAB_10029562:
    local_471 = '\x01';
LAB_10029569:
    piVar8 = piVar9;
    if ((((uint)piVar9 & 4) != 0) &&
       (piVar8 = (int *)((uint)piVar9 & 0xfffffffb), piVar10 != (int *)0x0)) {
      LOCK();
      piVar9 = piVar10 + 2;
      iVar6 = *piVar9;
      *piVar9 = *piVar9 + -1;
      UNLOCK();
      if (iVar6 == 1) {
        if (*piVar10 != 0) {
          (*local_484)(*piVar10);
          *piVar10 = 0;
        }
        if ((void *)piVar10[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)piVar10[1]);
          piVar10[1] = 0;
        }
        FUN_1002e346(piVar10);
      }
      local_478 = (int *)0x0;
    }
    if ((((uint)piVar8 & 2) != 0) &&
       (piVar8 = (int *)((uint)piVar8 & 0xfffffffd), piVar3 != (int *)0x0)) {
      LOCK();
      piVar10 = piVar3 + 2;
      iVar6 = *piVar10;
      *piVar10 = *piVar10 + -1;
      UNLOCK();
      if (iVar6 == 1) {
        if (*piVar3 != 0) {
          (*local_484)(*piVar3);
          *piVar3 = 0;
        }
        if ((void *)piVar3[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)piVar3[1]);
          piVar3[1] = 0;
        }
        FUN_1002e346(piVar3);
      }
      piVar3 = (int *)0x0;
    }
    piVar10 = local_480;
    local_8._0_1_ = 0xd;
    local_8._1_3_ = 0;
    if ((((uint)piVar8 & 1) != 0) &&
       (piVar8 = (int *)((uint)piVar8 & 0xfffffffe), local_480 != (int *)0x0)) {
      LOCK();
      piVar9 = local_480 + 2;
      iVar6 = *piVar9;
      *piVar9 = *piVar9 + -1;
      UNLOCK();
      if (iVar6 == 1) {
        if (*local_480 != 0) {
          (*local_484)(*local_480);
          *piVar10 = 0;
        }
        if ((void *)piVar10[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)piVar10[1]);
          piVar10[1] = 0;
        }
        FUN_1002e346(piVar10);
      }
    }
    if (local_471 != '\0') {
      piVar8 = FUN_100034b0(local_550,0x10,0x10061414);
      local_8._0_1_ = 0x14;
      if ((char)piVar8[0x12] != '\0') {
        FUN_100082c0(piVar8,L"found it");
      }
      FUN_10003240((int)local_4f0);
      local_8._0_1_ = 0x15;
      local_4f0[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_4f0);
      local_8._0_1_ = 0x16;
      if (local_2c._4_4_ != (int *)0x0) {
        (**(code **)(*local_2c._4_4_ + 8))(local_2c._4_4_);
      }
      local_8._0_1_ = 0x17;
      if ((int *)local_2c != (int *)0x0) {
        (**(code **)(*(int *)local_2c + 8))((int *)local_2c);
      }
      local_8._0_1_ = 0x18;
      if (local_24._4_4_ != (int *)0x0) {
        (**(code **)(*local_24._4_4_ + 8))(local_24._4_4_);
      }
      local_8._0_1_ = 0x19;
      if ((int *)local_24 != (int *)0x0) {
        (**(code **)(*(int *)local_24 + 8))((int *)local_24);
      }
      local_8._0_1_ = 0x1a;
      if (local_34._4_4_ != (int *)0x0) {
        (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
      }
      local_8 = CONCAT31(local_8._1_3_,0x1b);
      if ((int *)local_34 != (int *)0x0) {
        (**(code **)(*(int *)local_34 + 8))((int *)local_34);
      }
      if (7 < local_40) {
        ppppuVar4 = (undefined4 ****)local_54[0];
        if ((0xfff < local_40 * 2 + 2) &&
           (ppppuVar4 = (undefined4 ****)local_54[0][-1],
           0x1f < (uint)((int)local_54[0] + (-4 - (int)ppppuVar4)))) {
LAB_10029989:
          FUN_10032f7f();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_1002e346(ppppuVar4);
      }
      local_44 = 0;
      local_40 = 7;
      local_54[0] = (undefined4 ***)((uint)local_54[0] & 0xffff0000);
      FUN_1000c320((int)local_470);
      ExceptionList = local_10;
      FUN_1002e315(local_1c ^ (uint)&stack0xfffffffc);
      return;
    }
    local_3c = 0;
    local_38 = &PTR_vftable_10069aa8;
    FUN_1002bde0(&local_24,&local_3c);
    iVar6 = local_3c;
    ppuVar7 = local_38;
    if ((local_38[1] != DAT_10069aac) || (local_3c != 0)) goto LAB_10029963;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: Catch@10029887 @ 10029887