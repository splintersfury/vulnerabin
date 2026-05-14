void __thiscall FUN_1001ada0(void *this,int *param_1,undefined4 param_2,int *param_3,char param_4)

{
  int iVar1;
  byte *pbVar2;
  uint uVar3;
  uint uVar4;
  void *pvVar5;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004f6dd;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_8 = 0;
LAB_1001ade0:
  do {
    if ((char)param_2 == '\0') {
      if (param_1 == (int *)0x0) {
LAB_1001ae10:
        param_1 = (int *)0x0;
      }
      else {
        if ((*(byte **)param_1[7] == (byte *)0x0) || (*(int *)param_1[0xb] < 1)) {
          uVar4 = (**(code **)(*param_1 + 0x18))(uVar3);
        }
        else {
          uVar4 = (uint)**(byte **)param_1[7];
        }
        if (uVar4 == 0xffffffff) goto LAB_1001ae10;
        param_2._1_1_ = (undefined1)uVar4;
      }
      param_2._0_1_ = '\x01';
    }
    if (param_4 == '\0') {
      if (param_3 == (int *)0x0) {
LAB_1001ae57:
        param_3 = (int *)0x0;
      }
      else {
        if ((*(byte **)param_3[7] == (byte *)0x0) || (*(int *)param_3[0xb] < 1)) {
          uVar4 = (**(code **)(*param_3 + 0x18))();
        }
        else {
          uVar4 = (uint)**(byte **)param_3[7];
        }
        if (uVar4 == 0xffffffff) goto LAB_1001ae57;
      }
      param_4 = '\x01';
    }
    if (param_1 == (int *)0x0) {
      if (param_3 == (int *)0x0) {
        ExceptionList = local_10;
        return;
      }
    }
    else if (param_3 != (int *)0x0) {
      ExceptionList = local_10;
      return;
    }
    if ((char)param_2 == '\0') {
      if (param_1 != (int *)0x0) {
        if ((*(byte **)param_1[7] == (byte *)0x0) || (*(int *)param_1[0xb] < 1)) {
          uVar4 = (**(code **)(*param_1 + 0x18))();
        }
        else {
          uVar4 = (uint)**(byte **)param_1[7];
        }
        if (uVar4 != 0xffffffff) {
          param_2._1_1_ = (undefined1)uVar4;
          goto LAB_1001aeb4;
        }
      }
      param_1 = (int *)0x0;
    }
LAB_1001aeb4:
    uVar4 = *(uint *)((int)this + 0x10);
    if (uVar4 < *(uint *)((int)this + 0x14)) {
      *(uint *)((int)this + 0x10) = uVar4 + 1;
      pvVar5 = this;
      if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
        pvVar5 = *this;
      }
      *(undefined1 *)((int)pvVar5 + uVar4) = param_2._1_1_;
      *(undefined1 *)((int)pvVar5 + uVar4 + 1) = 0;
    }
    else {
      local_14 = local_14 & 0xffffff00;
      FUN_10014ac0(this,uVar4,local_14,param_2._1_1_);
    }
    if (param_1 == (int *)0x0) {
LAB_1001af2a:
      param_1 = (int *)0x0;
      param_2._0_1_ = '\x01';
      goto LAB_1001ade0;
    }
    if (*(int *)param_1[7] == 0) {
LAB_1001af16:
      uVar4 = (**(code **)(*param_1 + 0x1c))();
    }
    else {
      iVar1 = *(int *)param_1[0xb];
      if (iVar1 < 1) goto LAB_1001af16;
      *(int *)param_1[0xb] = iVar1 + -1;
      pbVar2 = *(byte **)param_1[7];
      *(byte **)param_1[7] = pbVar2 + 1;
      uVar4 = (uint)*pbVar2;
    }
    if (uVar4 == 0xffffffff) goto LAB_1001af2a;
    param_2._0_1_ = '\0';
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_1001af40 @ 1001af40