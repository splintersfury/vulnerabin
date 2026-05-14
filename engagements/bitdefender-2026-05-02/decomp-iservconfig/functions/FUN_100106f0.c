void __thiscall FUN_100106f0(void *this,int param_1)

{
  uint uVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  size_t sVar5;
  char cVar6;
  size_t _Count;
  char *local_34;
  int local_30;
  char local_29;
  undefined1 local_28 [32];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  if (param_1 == -1) {
    FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  uVar1 = **(uint **)((int)this + 0x20);
  cVar6 = (char)param_1;
  if (uVar1 != 0) {
    iVar4 = **(int **)((int)this + 0x30);
    if (uVar1 < iVar4 + uVar1) {
      **(int **)((int)this + 0x30) = iVar4 + -1;
      pcVar2 = (char *)**(int **)((int)this + 0x20);
      **(int **)((int)this + 0x20) = (int)(pcVar2 + 1);
      *pcVar2 = cVar6;
      goto LAB_10010747;
    }
  }
  if (*(int *)((int)this + 0x4c) != 0) {
    if (**(int **)((int)this + 0xc) == (int)this + 0x3c) {
      iVar4 = *(int *)((int)this + 0x54);
      iVar3 = *(int *)((int)this + 0x50);
      **(int **)((int)this + 0xc) = iVar3;
      **(int **)((int)this + 0x1c) = iVar3;
      **(int **)((int)this + 0x2c) = iVar4 - iVar3;
    }
    if (*(int **)((int)this + 0x38) == (int *)0x0) {
      _fputc((int)cVar6,*(FILE **)((int)this + 0x4c));
      FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    local_29 = cVar6;
    iVar4 = (**(code **)(**(int **)((int)this + 0x38) + 0x1c))
                      ((int)this + 0x40,&local_29,local_28,&local_34,local_28,&local_8,&local_30);
    if ((iVar4 == 0) || (iVar4 == 1)) {
      _Count = local_30 - (int)local_28;
      if (((_Count == 0) ||
          (sVar5 = _fwrite(local_28,1,_Count,*(FILE **)((int)this + 0x4c)), _Count == sVar5)) &&
         (*(undefined1 *)((int)this + 0x3d) = 1, local_34 != &local_29)) {
LAB_10010747:
        FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
    }
    else if (iVar4 == 3) {
      _fputc((int)local_29,*(FILE **)((int)this + 0x4c));
      FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10010860 @ 10010860