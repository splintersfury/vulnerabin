void __thiscall
FUN_1000fe20(void *this,int *param_1,uint param_2,int param_3,uint param_4,int param_5,int param_6,
            int param_7)

{
  int iVar1;
  char cVar2;
  int iVar3;
  undefined1 auStack_1c [4];
  int local_18;
  int local_14;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_1c;
  local_18 = param_2 + param_4;
  local_14 = param_3 + param_5 + (uint)CARRY4(param_2,param_4);
  if (*(int *)((int)this + 0x4c) != 0) {
    cVar2 = FUN_100119a0((int *)this);
    if (cVar2 != '\0') {
      iVar3 = _fsetpos(*(FILE **)((int)this + 0x4c),(fpos_t *)&local_18);
      if (iVar3 == 0) {
        *(int *)((int)this + 0x40) = param_6;
        *(int *)((int)this + 0x44) = param_7;
        if (**(int **)((int)this + 0xc) == (int)this + 0x3c) {
          iVar3 = *(int *)((int)this + 0x54);
          iVar1 = *(int *)((int)this + 0x50);
          **(int **)((int)this + 0xc) = iVar1;
          **(int **)((int)this + 0x1c) = iVar1;
          **(int **)((int)this + 0x2c) = iVar3 - iVar1;
        }
        iVar3 = *(int *)((int)this + 0x40);
        iVar1 = *(int *)((int)this + 0x44);
        *param_1 = local_18;
        param_1[1] = local_14;
        param_1[2] = 0;
        param_1[3] = 0;
        param_1[4] = iVar3;
        param_1[5] = iVar1;
        goto LAB_1000fee9;
      }
    }
  }
  *param_1 = -1;
  param_1[1] = -1;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
LAB_1000fee9:
  FUN_1002e315(local_c ^ (uint)auStack_1c);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ff00 @ 1000ff00