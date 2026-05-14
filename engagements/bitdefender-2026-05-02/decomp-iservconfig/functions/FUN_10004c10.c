undefined4 __thiscall FUN_10004c10(void *this,short param_1)

{
  uint uVar1;
  short *psVar2;
  uint *puVar3;
  int iVar4;
  short *psVar5;
  code *pcVar6;
  uint uVar7;
  uint *puVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  
  if ((*(byte *)((int)this + 0x3c) & 2) != 0) {
    return 0xffff;
  }
  if (param_1 != -1) {
    uVar1 = **(uint **)((int)this + 0x20);
    iVar10 = **(int **)((int)this + 0x30);
    uVar7 = uVar1 + iVar10 * 2;
    if ((uVar1 != 0) && (uVar1 < uVar7)) {
      **(int **)((int)this + 0x30) = iVar10 + -1;
      psVar2 = (short *)**(int **)((int)this + 0x20);
      **(int **)((int)this + 0x20) = (int)(psVar2 + 1);
      *psVar2 = param_1;
      *(uint *)((int)this + 0x38) = uVar1 + 2;
      return CONCAT22((short)(uVar1 >> 0x10),param_1);
    }
    uVar11 = 0;
    puVar3 = (uint *)**(undefined4 **)((int)this + 0xc);
    if ((uVar1 == 0) || (uVar11 = (int)(uVar7 - (int)puVar3) >> 1, uVar11 < 0x20)) {
      uVar7 = 0x20;
    }
    else if (uVar11 < 0x3fffffff) {
      uVar7 = uVar11 * 2;
    }
    else {
      if (0x7ffffffe < uVar11) {
        return 0xffff;
      }
      uVar7 = 0x7fffffff;
    }
    puVar8 = (uint *)FUN_10001e50(uVar7);
    uVar11 = uVar11 * 2;
    FUN_100301d0(puVar8,puVar3,uVar11);
    iVar10 = uVar11 + (int)puVar8;
    *(int *)((int)this + 0x38) = iVar10 + 2;
    **(undefined4 **)((int)this + 0x10) = puVar8;
    **(int **)((int)this + 0x20) = iVar10;
    **(int **)((int)this + 0x30) = (int)((uVar7 * 2 - iVar10) + (int)puVar8) >> 1;
    if ((*(byte *)((int)this + 0x3c) & 4) == 0) {
      iVar4 = *(int *)((int)this + 0x38);
      iVar10 = (int)puVar8 + (**(int **)((int)this + 0x1c) - (int)puVar3 >> 1) * 2;
      **(undefined4 **)((int)this + 0xc) = puVar8;
      **(int **)((int)this + 0x1c) = iVar10;
      **(int **)((int)this + 0x2c) = iVar4 - iVar10 >> 1;
    }
    else {
      **(undefined4 **)((int)this + 0xc) = puVar8;
      **(undefined4 **)((int)this + 0x1c) = 0;
      **(int **)((int)this + 0x2c) = (int)puVar8 >> 1;
    }
    uVar7 = *(uint *)((int)this + 0x3c);
    if ((uVar7 & 1) != 0) {
      puVar8 = puVar3;
      if ((0xfff < uVar11) &&
         (puVar8 = (uint *)puVar3[-1], 0x1f < (uint)((int)puVar3 + (-4 - (int)puVar8)))) {
        FUN_10032f7f();
        pcVar6 = (code *)swi(3);
        uVar9 = (*pcVar6)();
        return uVar9;
      }
      FUN_1002e346(puVar8);
      uVar7 = *(uint *)((int)this + 0x3c);
    }
    *(uint *)((int)this + 0x3c) = uVar7 | 1;
    **(int **)((int)this + 0x30) = **(int **)((int)this + 0x30) + -1;
    psVar5 = (short *)**(int **)((int)this + 0x20);
    psVar2 = psVar5 + 1;
    **(int **)((int)this + 0x20) = (int)psVar2;
    *psVar5 = param_1;
    return CONCAT22((short)((uint)psVar2 >> 0x10),param_1);
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004db0 @ 10004db0