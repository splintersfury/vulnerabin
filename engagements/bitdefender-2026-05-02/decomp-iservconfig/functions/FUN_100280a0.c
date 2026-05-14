void __fastcall
FUN_100280a0(undefined4 param_1,void *param_2,int *param_3,undefined4 param_4,int *param_5)

{
  code *pcVar1;
  char cVar2;
  uint uVar3;
  undefined4 uVar4;
  int *piVar5;
  int iVar6;
  short *psVar7;
  int local_d8 [24];
  undefined **local_78 [18];
  undefined4 local_30;
  int *local_2c;
  ushort local_28 [8];
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100505b3;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_2c = param_3;
  if ((undefined4 *)*param_3 == (undefined4 *)0x0) {
    uVar4 = 0;
  }
  else {
    uVar4 = *(undefined4 *)*param_3;
  }
  local_30 = param_1;
  local_18 = uVar3;
  FUN_1002c0e0(param_2,local_28,uVar4,param_5);
  local_8 = 0;
  if ((*(int *)(param_5[1] + 4) == DAT_10069aac) && (*param_5 == 0)) {
    if (local_28[0] != 8) {
      piVar5 = FUN_100034b0(local_d8,4,0x1006106c);
      local_8._0_1_ = 3;
      if ((char)piVar5[0x12] != '\0') {
        FUN_100082c0(piVar5,L"obect get type=");
        if ((char)piVar5[0x12] != '\0') {
          FUN_1002b770(piVar5,local_28[0]);
          if ((char)piVar5[0x12] != '\0') {
            FUN_100082c0(piVar5,L" expected=");
            if ((char)piVar5[0x12] != '\0') {
              FUN_1002b770(piVar5,8);
            }
          }
        }
      }
      FUN_10003240((int)local_78);
      local_8 = CONCAT31(local_8._1_3_,4);
      local_78[0] = std::ios_base::vftable;
      std::ios_base::_Ios_base_dtor((ios_base *)local_78);
      *param_5 = 0x648;
      param_5[1] = (int)&PTR_vftable_10069ab8;
      Ordinal_8(param_1);
      goto LAB_100281bc;
    }
  }
  else {
    piVar5 = FUN_100034b0(local_d8,4,0x1006106c);
    local_8 = CONCAT31(local_8._1_3_,1);
    cVar2 = (char)piVar5[0x12];
    if (cVar2 != '\0') {
      FUN_100082c0(piVar5,L"obect get ");
      cVar2 = (char)piVar5[0x12];
    }
    if ((undefined4 *)*local_2c == (undefined4 *)0x0) {
      psVar7 = (short *)0x0;
    }
    else {
      psVar7 = *(short **)*local_2c;
    }
    if (cVar2 != '\0') {
      FUN_100082c0(piVar5,psVar7);
      if ((char)piVar5[0x12] != '\0') {
        FUN_100082c0(piVar5,L" err=");
        if ((char)piVar5[0x12] != '\0') {
          FUN_10006730(piVar5,*param_5);
        }
      }
    }
    FUN_10003240((int)local_78);
    local_8._0_1_ = 2;
    local_78[0] = std::ios_base::vftable;
    std::ios_base::_Ios_base_dtor((ios_base *)local_78);
    local_8 = (uint)local_8._1_3_ << 8;
  }
  Ordinal_8(param_1,uVar3);
  iVar6 = Ordinal_10(param_1,local_28);
  if (iVar6 < 0) {
    FUN_1002f620(iVar6);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
LAB_100281bc:
  Ordinal_9(local_28);
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100282a0 @ 100282a0