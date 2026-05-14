undefined4 __thiscall FUN_10013b90(void *this,int *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined1 *puVar4;
  uint *puVar5;
  undefined1 uVar6;
  undefined1 local_d;
  uint local_c;
  uint local_8;
  
  uVar6 = *(undefined1 *)((int)this + 8);
  uVar1 = *(uint *)((int)this + 0x38);
  local_8 = CONCAT31(local_8._1_3_,uVar6);
  if (uVar1 < *(uint *)((int)this + 0x3c)) {
    *(uint *)((int)this + 0x38) = uVar1 + 1;
    puVar5 = (uint *)((int)this + 0x28);
    if (0xf < *(uint *)((int)this + 0x3c)) {
      puVar5 = *(uint **)((int)this + 0x28);
    }
    *(undefined1 *)((int)puVar5 + uVar1) = uVar6;
    *(undefined1 *)((int)puVar5 + uVar1 + 1) = 0;
  }
  else {
    local_c = local_c & 0xffffff00;
    puVar5 = FUN_10014ac0((void *)((int)this + 0x28),uVar1,local_c,uVar6);
  }
  if (param_1 != param_2) {
    do {
      *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + 1;
      *(int *)((int)this + 0x14) = *(int *)((int)this + 0x14) + 1;
      if (*(char *)((int)this + 0xc) == '\0') {
                    /* WARNING: Load size is inaccurate */
        uVar3 = (**(code **)**this)();
        *(undefined4 *)((int)this + 8) = uVar3;
      }
      else {
        *(undefined1 *)((int)this + 0xc) = 0;
      }
      puVar4 = *(undefined1 **)((int)this + 8);
      if (puVar4 != (undefined1 *)0xffffffff) {
        puVar5 = *(uint **)((int)this + 0x20);
        local_d = SUB41(puVar4,0);
        if (puVar5 == *(uint **)((int)this + 0x24)) {
          puVar4 = FUN_100174f0((void *)((int)this + 0x1c),puVar5,&local_d);
        }
        else {
          *(undefined1 *)puVar5 = local_d;
          *(int *)((int)this + 0x20) = *(int *)((int)this + 0x20) + 1;
        }
      }
      iVar2 = *(int *)((int)this + 8);
      if (iVar2 == 10) {
        *(int *)((int)this + 0x18) = *(int *)((int)this + 0x18) + 1;
        *(undefined4 *)((int)this + 0x14) = 0;
      }
      if ((iVar2 < *param_1) || (param_1[1] < iVar2)) {
        *(char **)((int)this + 0x40) = "invalid string: ill-formed UTF-8 byte";
        return (uint)puVar4 & 0xffffff00;
      }
      uVar1 = *(uint *)((int)this + 0x38);
      uVar6 = (undefined1)iVar2;
      local_c = CONCAT31(local_c._1_3_,uVar6);
      if (uVar1 < *(uint *)((int)this + 0x3c)) {
        *(uint *)((int)this + 0x38) = uVar1 + 1;
        puVar5 = (uint *)((int)this + 0x28);
        if (0xf < *(uint *)((int)this + 0x3c)) {
          puVar5 = *(uint **)((int)this + 0x28);
        }
        *(undefined1 *)((int)puVar5 + uVar1) = uVar6;
        *(undefined1 *)((int)puVar5 + uVar1 + 1) = 0;
      }
      else {
        local_8 = local_8 & 0xffffff00;
        puVar5 = FUN_10014ac0((void *)((int)this + 0x28),iVar2,local_8,uVar6);
      }
      param_1 = param_1 + 2;
    } while (param_1 != param_2);
  }
  return CONCAT31((int3)((uint)puVar5 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_10013cb0 @ 10013cb0