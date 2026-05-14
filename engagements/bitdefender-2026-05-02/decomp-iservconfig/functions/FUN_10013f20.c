void __thiscall FUN_10013f20(void *this,undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  size_t _Size;
  void *_Dst;
  int iVar2;
  code *pcVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  uint *local_1c;
  uint *local_18;
  uint local_14;
  
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffff0;
                    /* WARNING: Load size is inaccurate */
  uVar5 = param_3 + (param_2 - *this >> 2) * 0x20;
  if (*(int *)((int)this + 0xc) == 0x7fffffff) {
    FUN_10014110();
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  _Dst = *(void **)((int)this + 4);
                    /* WARNING: Load size is inaccurate */
  uVar8 = *(int *)((int)this + 0xc) + 0x20U >> 5;
  uVar6 = (int)_Dst - *this >> 2;
  local_1c = (uint *)0x0;
  if (uVar8 < uVar6) {
    *(uint *)((int)this + 4) = *this + uVar8 * 4;
  }
  else if (uVar6 < uVar8) {
                    /* WARNING: Load size is inaccurate */
    if ((uint)(*(int *)((int)this + 8) - *this >> 2) < uVar8) {
      FUN_10018e70(this,uVar8,(uint *)&local_1c);
    }
    else {
      local_18 = (uint *)0x0;
      _Size = (uVar8 - uVar6) * 4;
      _memset(_Dst,0,_Size);
      *(void **)((int)this + 4) = (void *)((int)_Dst + _Size);
    }
  }
  uVar6 = *(uint *)((int)this + 0xc);
  if (uVar6 == 0) {
    *(undefined4 *)((int)this + 0xc) = 1;
    puVar4 = local_1c;
  }
  else {
                    /* WARNING: Load size is inaccurate */
    iVar2 = *this;
    if (((int)uVar6 < 0) && (uVar6 != 0)) {
      iVar1 = -((~uVar6 >> 5) * 4 + 4);
    }
    else {
      iVar1 = (uVar6 >> 5) * 4;
    }
    local_1c = (uint *)(iVar2 + iVar1);
    puVar7 = (uint *)(uVar6 & 0x1f);
    uVar6 = uVar6 + 1;
    *(uint *)((int)this + 0xc) = uVar6;
    if (((int)uVar6 < 0) && (uVar6 != 0)) {
      iVar1 = -((~uVar6 >> 5) * 4 + 4);
    }
    else {
      iVar1 = (uVar6 >> 5) * 4;
    }
    puVar9 = (uint *)(iVar2 + iVar1);
    uVar6 = uVar6 & 0x1f;
    if (((int)uVar5 < 0) && (uVar5 != 0)) {
      iVar1 = -((~uVar5 >> 5) * 4 + 4);
    }
    else {
      iVar1 = (uVar5 >> 5) * 4;
    }
    local_18 = (uint *)(iVar2 + iVar1);
    while ((local_18 != local_1c ||
           (puVar4 = (uint *)(uVar5 & 0x1f), (uint *)(uVar5 & 0x1f) != puVar7))) {
      if (puVar7 == (uint *)0x0) {
        puVar7 = (uint *)0x1f;
        local_1c = local_1c + -1;
      }
      else {
        puVar7 = (uint *)((int)puVar7 - 1);
      }
      if (uVar6 == 0) {
        uVar6 = 0x1f;
        puVar9 = puVar9 + -1;
      }
      else {
        uVar6 = uVar6 - 1;
      }
      if ((*local_1c & 1 << ((byte)puVar7 & 0x1f)) == 0) {
        *puVar9 = *puVar9 & ~(1 << (uVar6 & 0x1f));
      }
      else {
        *puVar9 = *puVar9 | 1 << (uVar6 & 0x1f);
      }
    }
  }
  local_1c = puVar4;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014110 @ 10014110