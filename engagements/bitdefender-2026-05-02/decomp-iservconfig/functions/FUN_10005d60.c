uint * __thiscall FUN_10005d60(void *this,uint *param_1,uint param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  code *pcVar6;
  uint *puVar7;
  uint *puVar8;
  void *pvVar9;
  uint uVar10;
  
  uVar3 = *(uint *)((int)this + 0x14);
  iVar4 = *(int *)((int)this + 0x10);
  if (param_2 <= uVar3 - iVar4) {
    *(uint *)((int)this + 0x10) = param_2 + iVar4;
    pvVar9 = this;
    if (7 < uVar3) {
                    /* WARNING: Load size is inaccurate */
      pvVar9 = *this;
    }
    FUN_100301d0((uint *)((int)pvVar9 + iVar4 * 2),param_1,param_2 * 2);
    *(undefined2 *)((int)pvVar9 + (param_2 + iVar4) * 2) = 0;
    return (uint *)this;
  }
  if (0x7ffffffeU - iVar4 < param_2) {
    FUN_10001eb0();
  }
  else {
    uVar10 = param_2 + iVar4 | 7;
    if (uVar10 < 0x7fffffff) {
      if (0x7ffffffe - (uVar3 >> 1) < uVar3) {
        uVar10 = 0x7ffffffe;
      }
      else {
        uVar1 = (uVar3 >> 1) + uVar3;
        if (uVar10 < uVar1) {
          uVar10 = uVar1;
        }
      }
    }
    else {
      uVar10 = 0x7ffffffe;
    }
    puVar7 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar10) | uVar10 + 1);
    *(uint *)((int)this + 0x10) = param_2 + iVar4;
    *(uint *)((int)this + 0x14) = uVar10;
    puVar8 = (uint *)(iVar4 * 2 + (int)puVar7);
    puVar2 = (undefined2 *)((int)puVar7 + (param_2 + iVar4) * 2);
    if (uVar3 < 8) {
      FUN_100301d0(puVar7,(uint *)this,iVar4 * 2);
      FUN_100301d0(puVar8,param_1,param_2 * 2);
      *puVar2 = 0;
      *(uint **)this = puVar7;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar5 = *this;
    FUN_100301d0(puVar7,puVar5,iVar4 * 2);
    FUN_100301d0(puVar8,param_1,param_2 * 2);
    *puVar2 = 0;
    puVar8 = puVar5;
    if ((uVar3 * 2 + 2 < 0x1000) ||
       (puVar8 = (uint *)puVar5[-1], (uint)((int)puVar5 + (-4 - (int)puVar8)) < 0x20)) {
      FUN_1002e346(puVar8);
      *(uint **)this = puVar7;
      return (uint *)this;
    }
  }
  FUN_10032f7f();
  pcVar6 = (code *)swi(3);
  puVar8 = (uint *)(*pcVar6)();
  return puVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005ef0 @ 10005ef0