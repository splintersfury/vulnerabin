void __fastcall FUN_10029ab0(void *param_1,uint *param_2,wchar_t *param_3)

{
  uint *puVar1;
  int *piVar2;
  uint uVar3;
  char cVar4;
  int *piVar5;
  undefined4 ****ppppuVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined **extraout_ECX_01;
  undefined **ppuVar9;
  uint *puVar10;
  code *pcVar11;
  uint uStack_570;
  int local_560 [24];
  undefined **local_500 [18];
  int local_4b8 [6];
  void *local_4a0;
  wchar_t *local_49c;
  code *local_498;
  uint *local_494;
  int *local_490;
  code *local_48c;
  undefined1 local_488 [1048];
  short local_70 [10];
  undefined4 ***local_5c [4];
  undefined4 local_4c;
  uint local_48;
  int local_44;
  undefined **local_40;
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
  puStack_c = &LAB_100509c1;
  local_10 = ExceptionList;
  uStack_570 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_570;
  ExceptionList = &local_10;
  local_49c = param_3;
  local_4a0 = param_1;
  local_1c = uStack_570;
  FUN_1000c210(local_488,L"search_diskdrives_partitions");
  local_8 = 0;
  piVar5 = FUN_100034b0(local_560,0x10,0x10061490);
  local_8._0_1_ = 1;
  if (((char)piVar5[0x12] != '\0') && (FUN_100082c0(piVar5,L"devid="), (char)piVar5[0x12] != '\0'))
  {
    FUN_100082c0(piVar5,(short *)param_2);
  }
  FUN_10003240((int)local_500);
  local_8._0_1_ = 2;
  local_500[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_500);
  local_8._0_1_ = 0;
  FUN_10027f40(local_5c,param_2);
  local_8._0_1_ = 4;
  ppppuVar6 = local_5c;
  if (7 < local_48) {
    ppppuVar6 = (undefined4 ****)local_5c[0];
  }
  local_34 = 0;
  piVar5 = FUN_100277f0(&local_494,(int)ppppuVar6);
  local_8 = CONCAT31(local_8._1_3_,5);
  if ((undefined4 *)*piVar5 == (undefined4 *)0x0) {
    uVar7 = 0;
  }
  else {
    uVar7 = *(undefined4 *)*piVar5;
  }
  FUN_1002c2f0(param_1,(undefined4 *)&local_34,uVar7);
  puVar10 = local_494;
  if (local_494 != (uint *)0x0) {
    LOCK();
    puVar1 = local_494 + 2;
    uVar3 = *puVar1;
    *puVar1 = *puVar1 - 1;
    UNLOCK();
    if ((uVar3 == 1) && (local_494 != (uint *)0x0)) {
      if (*local_494 == 0) {
        local_48c = Ordinal_6_exref;
      }
      else {
        local_48c = Ordinal_6_exref;
        Ordinal_6(*local_494);
        *puVar10 = 0;
      }
      if ((void *)puVar10[1] != (void *)0x0) {
        thunk_FUN_100330ca((void *)puVar10[1]);
        puVar10[1] = 0;
      }
      FUN_1002e346(puVar10);
      goto LAB_10029c37;
    }
  }
  local_48c = Ordinal_6_exref;
LAB_10029c37:
  pcVar11 = local_48c;
  piVar5 = (int *)local_34;
  local_24 = 0;
  local_8._0_1_ = 8;
  if ((int *)local_34 != (int *)0x0) {
    (**(code **)(*(int *)local_34 + 4))((int *)local_34);
  }
  piVar2 = local_34._4_4_;
  local_8._0_1_ = 9;
  if (local_34._4_4_ != (int *)0x0) {
    (**(code **)(*local_34._4_4_ + 4))(local_34._4_4_);
  }
  local_24 = CONCAT44(piVar2,piVar5);
  local_2c = 0;
  local_8._0_1_ = 0xd;
  local_498 = Ordinal_2_exref;
  while( true ) {
    cVar4 = FUN_1002bf50(&local_24,(int *)&local_2c);
    if (cVar4 != '\0') {
      local_8._0_1_ = 0x19;
      if (local_2c._4_4_ != (int *)0x0) {
        (**(code **)(*local_2c._4_4_ + 8))(local_2c._4_4_);
      }
      local_8._0_1_ = 0x1a;
      if ((int *)local_2c != (int *)0x0) {
        (**(code **)(*(int *)local_2c + 8))((int *)local_2c);
      }
      local_8._0_1_ = 0x1b;
      if (local_24._4_4_ != (int *)0x0) {
        (**(code **)(*local_24._4_4_ + 8))(local_24._4_4_);
      }
      local_8._0_1_ = 0x1c;
      if ((int *)local_24 != (int *)0x0) {
        (**(code **)(*(int *)local_24 + 8))((int *)local_24);
      }
      local_8._0_1_ = 0x1d;
      if (local_34._4_4_ != (int *)0x0) {
        (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
      }
      local_8 = CONCAT31(local_8._1_3_,0x1e);
      if ((int *)local_34 != (int *)0x0) {
        (**(code **)(*(int *)local_34 + 8))((int *)local_34);
      }
      if (7 < local_48) {
        ppppuVar6 = (undefined4 ****)local_5c[0];
        if ((0xfff < local_48 * 2 + 2) &&
           (ppppuVar6 = (undefined4 ****)local_5c[0][-1],
           0x1f < (uint)((int)local_5c[0] + (-4 - (int)ppppuVar6)))) {
          FUN_10032f7f();
          pcVar11 = (code *)swi(3);
          (*pcVar11)();
          return;
        }
        FUN_1002e346(ppppuVar6);
      }
      local_4c = 0;
      local_48 = 7;
      local_5c[0] = (undefined4 ***)((uint)local_5c[0] & 0xffff0000);
      FUN_1002a06d();
      return;
    }
    local_44 = 0;
    local_40 = &PTR_vftable_10069aa8;
    piVar5 = (int *)operator_new(0xc);
    local_8._0_1_ = 0xe;
    if (piVar5 != (int *)0x0) break;
    piVar5 = (int *)0x0;
    uVar7 = extraout_ECX;
LAB_10029cfb:
    local_8._0_1_ = 0xd;
    local_490 = piVar5;
    if (piVar5 == (int *)0x0) goto LAB_1002a0a0;
    local_8._0_1_ = 0xf;
    FUN_100280a0(local_70,(void *)((int)&local_24 + 4),(int *)&local_490,uVar7,&local_44);
    piVar5 = local_490;
    local_8._0_1_ = 0x11;
    if (local_490 != (int *)0x0) {
      LOCK();
      piVar2 = local_490 + 2;
      iVar8 = *piVar2;
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if (iVar8 == 1) {
        if (*local_490 != 0) {
          (*pcVar11)(*local_490);
          *piVar5 = 0;
        }
        if ((void *)piVar5[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)piVar5[1]);
          piVar5[1] = 0;
        }
        FUN_1002e346(piVar5);
      }
    }
    if ((local_40[1] == DAT_10069aac) && (local_44 == 0)) {
      piVar5 = (int *)FUN_10027a20(&local_494,local_70);
      local_8._0_1_ = 0x12;
      if ((undefined4 *)*piVar5 == (undefined4 *)0x0) {
        puVar10 = (uint *)0x0;
      }
      else {
        puVar10 = *(uint **)*piVar5;
      }
      cVar4 = FUN_100291a0(local_4a0,puVar10,local_49c);
      puVar10 = local_494;
      if (local_494 != (uint *)0x0) {
        LOCK();
        puVar1 = local_494 + 2;
        uVar3 = *puVar1;
        *puVar1 = *puVar1 - 1;
        UNLOCK();
        if ((uVar3 == 1) && (local_494 != (uint *)0x0)) {
          if (*local_494 != 0) {
            uStack_570 = *local_494;
            (*local_48c)();
            *puVar10 = 0;
          }
          if ((void *)puVar10[1] != (void *)0x0) {
            thunk_FUN_100330ca((void *)puVar10[1]);
            puVar10[1] = 0;
          }
          FUN_1002e346(puVar10);
        }
        local_494 = (uint *)0x0;
      }
      if (cVar4 == '\0') goto LAB_10029ef8;
      Ordinal_9(local_70);
      local_8._0_1_ = 0x13;
      if (local_2c._4_4_ != (int *)0x0) {
        (**(code **)(*local_2c._4_4_ + 8))(local_2c._4_4_);
      }
      local_8._0_1_ = 0x14;
      if ((int *)local_2c != (int *)0x0) {
        (**(code **)(*(int *)local_2c + 8))((int *)local_2c);
      }
      local_8._0_1_ = 0x15;
      if (local_24._4_4_ != (int *)0x0) {
        (**(code **)(*local_24._4_4_ + 8))(local_24._4_4_);
      }
      local_8._0_1_ = 0x16;
      if ((int *)local_24 != (int *)0x0) {
        (**(code **)(*(int *)local_24 + 8))((int *)local_24);
      }
      local_8._0_1_ = 0x17;
      if (local_34._4_4_ != (int *)0x0) {
        (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
      }
      local_8._0_1_ = 0x18;
      if ((int *)local_34 != (int *)0x0) {
        (**(code **)(*(int *)local_34 + 8))((int *)local_34);
      }
      if (local_48 < 8) {
LAB_10029ece:
        local_4c = 0;
        local_48 = 7;
        local_5c[0] = (undefined4 ***)((uint)local_5c[0] & 0xffff0000);
        FUN_1000c320((int)local_488);
        ExceptionList = local_10;
        FUN_1002e315(local_1c ^ (uint)&stack0xfffffffc);
        return;
      }
      ppppuVar6 = (undefined4 ****)local_5c[0];
      if ((local_48 * 2 + 2 < 0x1000) ||
         (ppppuVar6 = (undefined4 ****)local_5c[0][-1],
         (uint)((int)local_5c[0] + (-4 - (int)ppppuVar6)) < 0x20)) {
        FUN_1002e346(ppppuVar6);
        goto LAB_10029ece;
      }
      goto LAB_1002a0aa;
    }
LAB_10029ef8:
    local_8._0_1_ = 0xd;
    Ordinal_9(local_70);
    local_3c = 0;
    local_38 = &PTR_vftable_10069aa8;
    FUN_1002bde0(&local_24,&local_3c);
    iVar8 = local_3c;
    ppuVar9 = local_38;
    if ((local_38[1] != DAT_10069aac) || (pcVar11 = local_48c, local_3c != 0)) goto LAB_1002a0af;
  }
  *piVar5 = 0;
  piVar5[1] = 0;
  piVar5[2] = 1;
  local_490 = piVar5;
  iVar8 = (*local_498)(L"DeviceID");
  *piVar5 = iVar8;
  uVar7 = extraout_ECX_00;
  if (iVar8 != 0) goto LAB_10029cfb;
  FUN_1002f620(0x8007000e);
LAB_1002a0a0:
  FUN_1002f620(0x8007000e);
LAB_1002a0aa:
  iVar8 = FUN_10032f7f();
  ppuVar9 = extraout_ECX_01;
LAB_1002a0af:
  FUN_10027cd0(local_4b8,(uint *)"objects_iterator::increment failed",iVar8,(int *)ppuVar9);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_4b8,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: Catch@10029ff6 @ 10029ff6