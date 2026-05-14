void __thiscall FUN_1000ff00(void *this,undefined4 *param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char cVar4;
  int iVar5;
  int unaff_EDI;
  bool bVar6;
  int local_1c;
  undefined4 local_18;
  undefined4 local_14;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)&local_1c;
  if (((**(int **)((int)this + 0x1c) == (int)this + 0x3c) && (param_4 == 1)) &&
     (*(int *)((int)this + 0x38) == 0)) {
    bVar6 = param_2 != 0;
    param_2 = param_2 + -1;
    param_3 = param_3 + -1 + (uint)bVar6;
  }
  local_1c = param_3;
  if ((((*(int *)((int)this + 0x4c) == 0) || (cVar4 = FUN_100119a0((int *)this), cVar4 == '\0')) ||
      (((param_2 != 0 || local_1c != 0 || (param_4 != 1)) &&
       (iVar5 = __fseeki64(*(FILE **)((int)this + 0x4c),CONCAT44(param_4,local_1c),unaff_EDI),
       iVar5 != 0)))) ||
     (iVar5 = _fgetpos(*(FILE **)((int)this + 0x4c),(fpos_t *)&local_18), iVar5 != 0)) {
    *param_1 = 0xffffffff;
    param_1[1] = 0xffffffff;
    param_1[2] = 0;
    param_1[3] = 0;
    *(undefined8 *)(param_1 + 4) = 0;
  }
  else {
    if (**(int **)((int)this + 0xc) == (int)this + 0x3c) {
      iVar5 = *(int *)((int)this + 0x54);
      iVar1 = *(int *)((int)this + 0x50);
      **(int **)((int)this + 0xc) = iVar1;
      **(int **)((int)this + 0x1c) = iVar1;
      **(int **)((int)this + 0x2c) = iVar5 - iVar1;
    }
    uVar2 = *(undefined4 *)((int)this + 0x40);
    uVar3 = *(undefined4 *)((int)this + 0x44);
    *param_1 = local_18;
    param_1[1] = local_14;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = uVar2;
    param_1[5] = uVar3;
  }
  FUN_1002e315(local_c ^ (uint)&local_1c);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10010020 @ 10010020

/* WARNING: Removing unreachable block (ram,0x10010073) */
/* WARNING: Removing unreachable block (ram,0x1001007d) */