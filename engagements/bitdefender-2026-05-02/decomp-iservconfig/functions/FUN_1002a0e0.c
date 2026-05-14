void __fastcall FUN_1002a0e0(uint *param_1,void *param_2,wchar_t *param_3)

{
  int *piVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  uint *puVar8;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 uVar9;
  void *pvVar10;
  undefined **extraout_ECX_03;
  undefined **ppuVar11;
  uint uStack_5a8;
  int local_598 [24];
  undefined **local_538 [19];
  int local_4ec [6];
  wchar_t *local_4d4;
  uint *local_4d0;
  void *local_4cc;
  int *local_4c8;
  code *local_4c4;
  uint *local_4c0;
  code *local_4bc;
  code *local_4b8;
  char local_4b1;
  uint *local_4b0;
  int *local_4ac;
  undefined1 local_4a8 [1048];
  short local_90 [8];
  void *local_80 [4];
  int local_70;
  uint local_6c;
  short local_68 [10];
  int local_54;
  undefined **local_50;
  undefined8 local_4c;
  undefined8 local_44;
  int local_3c;
  undefined **local_38;
  undefined8 local_34;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_10050abe;
  local_1c = ExceptionList;
  uStack_5a8 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_5a8;
  ExceptionList = &local_1c;
  local_4d4 = param_3;
  local_4d0 = param_1;
  local_4cc = param_2;
  local_4c0 = param_1;
  local_4b0 = param_1;
  local_2c = uStack_5a8;
  FUN_1000c210(local_4a8,L"search_disks");
  local_14 = 0;
  piVar4 = FUN_100034b0(local_598,0x10,0x100614cc);
  local_14._0_1_ = 1;
  if (((char)piVar4[0x12] != '\0') &&
     (FUN_100082c0(piVar4,L"search for partition "), (char)piVar4[0x12] != '\0')) {
    FUN_100082c0(piVar4,param_3);
  }
  FUN_10003240((int)local_538);
  local_14._0_1_ = 2;
  local_538[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_538);
  local_70 = 0;
  local_6c = 7;
  local_80[0] = (void *)0x0;
  local_14._0_1_ = 4;
  local_4c = 0;
  puVar5 = (uint *)operator_new(0xc);
  local_14._0_1_ = 5;
  if (puVar5 == (uint *)0x0) {
    puVar5 = (uint *)0x0;
    local_4c4 = Ordinal_2_exref;
LAB_1002a249:
    local_14._0_1_ = 4;
    local_4b0 = puVar5;
    if (puVar5 != (uint *)0x0) {
      local_14 = CONCAT31(local_14._1_3_,6);
      FUN_1002c2f0(local_4cc,(undefined4 *)&local_4c,*puVar5);
      LOCK();
      puVar8 = puVar5 + 2;
      uVar6 = *puVar8;
      *puVar8 = *puVar8 - 1;
      UNLOCK();
      if (uVar6 == 1) {
        if (*puVar5 == 0) {
          local_4b8 = Ordinal_6_exref;
        }
        else {
          local_4b8 = Ordinal_6_exref;
          Ordinal_6(*puVar5);
          *puVar5 = 0;
        }
        if ((void *)puVar5[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)puVar5[1]);
          puVar5[1] = 0;
        }
        FUN_1002e346(puVar5);
      }
      else {
        local_4b8 = Ordinal_6_exref;
      }
      piVar4 = (int *)local_4c;
      local_34 = 0;
      local_14._0_1_ = 9;
      if ((int *)local_4c != (int *)0x0) {
        (**(code **)(*(int *)local_4c + 4))((int *)local_4c);
      }
      piVar1 = local_4c._4_4_;
      local_14._0_1_ = 10;
      if (local_4c._4_4_ != (int *)0x0) {
        (**(code **)(*local_4c._4_4_ + 4))(local_4c._4_4_);
      }
      local_34 = CONCAT44(piVar1,piVar4);
      local_44 = 0;
      local_14._0_1_ = 0xe;
      local_4bc = Ordinal_9_exref;
      do {
        cVar3 = FUN_1002bf50(&local_34,(int *)&local_44);
        if (cVar3 != '\0') {
          local_14._0_1_ = 0x20;
          if (local_44._4_4_ != (int *)0x0) {
            (**(code **)(*local_44._4_4_ + 8))(local_44._4_4_);
          }
          local_14._0_1_ = 0x21;
          if ((int *)local_44 != (int *)0x0) {
            (**(code **)(*(int *)local_44 + 8))((int *)local_44);
          }
          local_14._0_1_ = 0x22;
          if (local_34._4_4_ != (int *)0x0) {
            (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
          }
          local_14._0_1_ = 0x23;
          if ((int *)local_34 != (int *)0x0) {
            (**(code **)(*(int *)local_34 + 8))((int *)local_34);
          }
          local_14._0_1_ = 0x24;
          if (local_4c._4_4_ != (int *)0x0) {
            (**(code **)(*local_4c._4_4_ + 8))(local_4c._4_4_);
          }
          local_14 = CONCAT31(local_14._1_3_,0x25);
          if ((int *)local_4c != (int *)0x0) {
            (**(code **)(*(int *)local_4c + 8))((int *)local_4c);
          }
          FUN_1002a926();
          return;
        }
        local_3c = 0;
        local_38 = &PTR_vftable_10069aa8;
        piVar4 = (int *)operator_new(0xc);
        local_14._0_1_ = 0xf;
        if (piVar4 == (int *)0x0) {
          piVar4 = (int *)0x0;
          uVar9 = extraout_ECX;
        }
        else {
          *piVar4 = 0;
          piVar4[1] = 0;
          piVar4[2] = 1;
          local_4ac = piVar4;
          iVar7 = (*local_4c4)(L"SerialNumber");
          *piVar4 = iVar7;
          uVar9 = extraout_ECX_00;
          if (iVar7 == 0) goto LAB_1002a98a;
        }
        local_14._0_1_ = 0xe;
        local_4ac = piVar4;
        if (piVar4 == (int *)0x0) goto LAB_1002a994;
        local_14._0_1_ = 0x10;
        FUN_100280a0(local_68,(void *)((int)&local_34 + 4),(int *)&local_4ac,uVar9,&local_3c);
        piVar4 = local_4ac;
        local_14._0_1_ = 0x12;
        if (local_4ac != (int *)0x0) {
          LOCK();
          piVar1 = local_4ac + 2;
          iVar7 = *piVar1;
          *piVar1 = *piVar1 + -1;
          UNLOCK();
          if (iVar7 == 1) {
            if (*local_4ac != 0) {
              (*local_4b8)(*local_4ac);
              *piVar4 = 0;
            }
            if ((void *)piVar4[1] != (void *)0x0) {
              thunk_FUN_100330ca((void *)piVar4[1]);
              piVar4[1] = 0;
            }
            FUN_1002e346(piVar4);
          }
        }
        if ((local_38[1] == DAT_10069aac) && (local_3c == 0)) {
          if (local_70 == 0) {
            piVar4 = (int *)FUN_10027a20(&local_4c8,local_68);
            local_14._0_1_ = 0x13;
            if ((undefined4 *)*piVar4 == (undefined4 *)0x0) {
              puVar5 = (uint *)0x0;
            }
            else {
              puVar5 = *(uint **)*piVar4;
            }
            puVar8 = puVar5;
            do {
              uVar6 = *puVar8;
              puVar8 = (uint *)((int)puVar8 + 2);
            } while ((short)uVar6 != 0);
            FUN_10001d40(local_80,puVar5,(int)puVar8 - ((int)puVar5 + 2) >> 1);
            piVar4 = local_4c8;
            local_14._0_1_ = 0x12;
            if (local_4c8 != (int *)0x0) {
              LOCK();
              piVar1 = local_4c8 + 2;
              iVar7 = *piVar1;
              *piVar1 = *piVar1 + -1;
              UNLOCK();
              if ((iVar7 == 1) && (local_4c8 != (int *)0x0)) {
                if (*local_4c8 != 0) {
                  (*local_4b8)(*local_4c8);
                  *piVar4 = 0;
                }
                if ((void *)piVar4[1] != (void *)0x0) {
                  thunk_FUN_100330ca((void *)piVar4[1]);
                  piVar4[1] = 0;
                }
                FUN_1002e346(piVar4);
              }
              local_4c8 = (int *)0x0;
            }
          }
          piVar4 = (int *)operator_new(0xc);
          local_14._0_1_ = 0x14;
          if (piVar4 == (int *)0x0) {
            piVar4 = (int *)0x0;
            uVar9 = extraout_ECX_01;
          }
          else {
            *piVar4 = 0;
            piVar4[1] = 0;
            piVar4[2] = 1;
            local_4ac = piVar4;
            iVar7 = (*local_4c4)(L"DeviceID");
            *piVar4 = iVar7;
            uVar9 = extraout_ECX_02;
            if (iVar7 == 0) goto LAB_1002a99e;
          }
          local_14._0_1_ = 0x12;
          local_4ac = piVar4;
          if (piVar4 != (int *)0x0) {
            local_14._0_1_ = 0x15;
            FUN_100280a0(local_90,(void *)((int)&local_34 + 4),(int *)&local_4ac,uVar9,&local_3c);
            piVar4 = local_4ac;
            local_14._0_1_ = 0x17;
            if (local_4ac != (int *)0x0) {
              LOCK();
              piVar1 = local_4ac + 2;
              iVar7 = *piVar1;
              *piVar1 = *piVar1 + -1;
              UNLOCK();
              if (iVar7 == 1) {
                if (*local_4ac != 0) {
                  (*local_4b8)(*local_4ac);
                  *piVar4 = 0;
                }
                if ((void *)piVar4[1] != (void *)0x0) {
                  thunk_FUN_100330ca((void *)piVar4[1]);
                  piVar4[1] = 0;
                }
                FUN_1002e346(piVar4);
              }
            }
            if ((local_38[1] != DAT_10069aac) || (local_3c != 0)) {
LAB_1002a7d9:
              pcVar2 = local_4bc;
              (*local_4bc)(local_90);
              local_14._0_1_ = 0xe;
              (*pcVar2)(local_68);
              goto LAB_1002a7ff;
            }
            piVar4 = (int *)FUN_10027a20(&local_4b0,local_90);
            local_14._0_1_ = 0x18;
            if ((undefined4 *)*piVar4 == (undefined4 *)0x0) {
              puVar5 = (uint *)0x0;
            }
            else {
              puVar5 = *(uint **)*piVar4;
            }
            local_4b1 = FUN_10029ab0(local_4cc,puVar5,local_4d4);
            puVar5 = local_4b0;
            local_14._0_1_ = 0x17;
            if (local_4b0 != (uint *)0x0) {
              LOCK();
              puVar8 = local_4b0 + 2;
              uVar6 = *puVar8;
              *puVar8 = *puVar8 - 1;
              UNLOCK();
              if ((uVar6 == 1) && (local_4b0 != (uint *)0x0)) {
                if (*local_4b0 != 0) {
                  uStack_5a8 = *local_4b0;
                  (*local_4b8)();
                  *puVar5 = 0;
                }
                if ((void *)puVar5[1] != (void *)0x0) {
                  thunk_FUN_100330ca((void *)puVar5[1]);
                  puVar5[1] = 0;
                }
                FUN_1002e346(puVar5);
              }
              local_4b0 = (uint *)0x0;
            }
            if (local_4b1 == '\0') goto LAB_1002a7d9;
            piVar4 = (int *)FUN_10027a20(&local_4b0,local_68);
            local_14 = CONCAT31(local_14._1_3_,0x19);
            if ((undefined4 *)*piVar4 == (undefined4 *)0x0) {
              puVar5 = (uint *)0x0;
            }
            else {
              puVar5 = *(uint **)*piVar4;
            }
            *local_4c0 = 0;
            local_4c0[4] = 0;
            local_4c0[5] = 7;
            *(undefined2 *)local_4c0 = 0;
            puVar8 = puVar5;
            do {
              uVar6 = *puVar8;
              puVar8 = (uint *)((int)puVar8 + 2);
            } while ((short)uVar6 != 0);
            FUN_10001d40(local_4c0,puVar5,(int)puVar8 - ((int)puVar5 + 2) >> 1);
            puVar5 = local_4b0;
            if (local_4b0 != (uint *)0x0) {
              LOCK();
              puVar8 = local_4b0 + 2;
              uVar6 = *puVar8;
              *puVar8 = *puVar8 - 1;
              UNLOCK();
              if ((uVar6 == 1) && (local_4b0 != (uint *)0x0)) {
                if (*local_4b0 != 0) {
                  (*local_4b8)(*local_4b0);
                  *puVar5 = 0;
                }
                if ((void *)puVar5[1] != (void *)0x0) {
                  thunk_FUN_100330ca((void *)puVar5[1]);
                  puVar5[1] = 0;
                }
                FUN_1002e346(puVar5);
              }
              local_4b0 = (uint *)0x0;
            }
            pcVar2 = local_4bc;
            (*local_4bc)(local_90);
            (*pcVar2)(local_68);
            local_14._0_1_ = 0x1a;
            if (local_44._4_4_ != (int *)0x0) {
              (**(code **)(*local_44._4_4_ + 8))(local_44._4_4_);
            }
            local_14._0_1_ = 0x1b;
            if ((int *)local_44 != (int *)0x0) {
              (**(code **)(*(int *)local_44 + 8))((int *)local_44);
            }
            local_14._0_1_ = 0x1c;
            if (local_34._4_4_ != (int *)0x0) {
              (**(code **)(*local_34._4_4_ + 8))(local_34._4_4_);
            }
            local_14._0_1_ = 0x1d;
            if ((int *)local_34 != (int *)0x0) {
              (**(code **)(*(int *)local_34 + 8))((int *)local_34);
            }
            local_14._0_1_ = 0x1e;
            if (local_4c._4_4_ != (int *)0x0) {
              (**(code **)(*local_4c._4_4_ + 8))(local_4c._4_4_);
            }
            local_14._0_1_ = 0x1f;
            if ((int *)local_4c != (int *)0x0) {
              (**(code **)(*(int *)local_4c + 8))((int *)local_4c);
            }
            if (local_6c < 8) {
LAB_1002a7c3:
              FUN_1000c320((int)local_4a8);
              ExceptionList = local_1c;
              FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
              return;
            }
            pvVar10 = local_80[0];
            if ((local_6c * 2 + 2 < 0x1000) ||
               (pvVar10 = *(void **)((int)local_80[0] + -4),
               (uint)((int)local_80[0] + (-4 - (int)pvVar10)) < 0x20)) {
              FUN_1002e346(pvVar10);
              goto LAB_1002a7c3;
            }
            goto LAB_1002a9b2;
          }
          goto LAB_1002a9a8;
        }
        local_14._0_1_ = 0xe;
        (*local_4bc)(local_68);
LAB_1002a7ff:
        local_54 = 0;
        local_50 = &PTR_vftable_10069aa8;
        FUN_1002bde0(&local_34,&local_54);
        iVar7 = local_54;
        ppuVar11 = local_50;
      } while ((local_50[1] == DAT_10069aac) && (local_54 == 0));
      goto LAB_1002a9b7;
    }
  }
  else {
    *puVar5 = 0;
    local_4c4 = Ordinal_2_exref;
    puVar5[1] = 0;
    puVar5[2] = 1;
    local_4b0 = puVar5;
    uVar6 = Ordinal_2(L"SELECT SerialNumber, DeviceID FROM Win32_DiskDrive");
    *puVar5 = uVar6;
    if (uVar6 != 0) goto LAB_1002a249;
    FUN_1002f620(0x8007000e);
  }
  FUN_1002f620(0x8007000e);
LAB_1002a98a:
  FUN_1002f620(0x8007000e);
LAB_1002a994:
  FUN_1002f620(0x8007000e);
LAB_1002a99e:
  FUN_1002f620(0x8007000e);
LAB_1002a9a8:
  FUN_1002f620(0x8007000e);
LAB_1002a9b2:
  iVar7 = FUN_10032f7f();
  ppuVar11 = extraout_ECX_03;
LAB_1002a9b7:
  FUN_10027cd0(local_4ec,(uint *)"objects_iterator::increment failed",iVar7,(int *)ppuVar11);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_4ec,&DAT_10067674);
}


// FUNCTION_END

// FUNCTION_START: Catch@1002a8a9 @ 1002a8a9