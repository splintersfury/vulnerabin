uint * __thiscall FUN_100055a0(void *this,uint *param_1)

{
  int iVar1;
  void *pvVar2;
  uint *puVar3;
  uint *puVar4;
  uint uVar5;
  
  puVar3 = param_1;
  puVar4 = param_1;
  do {
    uVar5 = *puVar4;
    puVar4 = (uint *)((int)puVar4 + 1);
  } while ((char)uVar5 != '\0');
  uVar5 = (int)puVar4 - ((int)param_1 + 1);
  iVar1 = *(int *)((int)this + 0x10);
  if (uVar5 <= *(uint *)((int)this + 0x14) - iVar1) {
    *(uint *)((int)this + 0x10) = iVar1 + uVar5;
    pvVar2 = this;
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      pvVar2 = *this;
    }
    FUN_100301d0((uint *)((int)pvVar2 + iVar1),param_1,uVar5);
    *(undefined1 *)((int)pvVar2 + iVar1 + uVar5) = 0;
    return (uint *)this;
  }
  param_1 = (uint *)((uint)param_1 & 0xffffff00);
  puVar3 = FUN_100062b0(this,uVar5,param_1,puVar3,uVar5);
  return puVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005610 @ 10005610