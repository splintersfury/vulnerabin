uint __thiscall FUN_10004ba0(void *this,ushort param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)((int)this + 0x1c);
  uVar1 = *puVar2;
  if (((uVar1 != 0) && (puVar2 = *(uint **)((int)this + 0xc), *puVar2 < uVar1)) &&
     ((param_1 == 0xffff ||
      ((param_1 == *(ushort *)(uVar1 - 2) || ((*(byte *)((int)this + 0x3c) & 2) == 0)))))) {
    **(int **)((int)this + 0x2c) = **(int **)((int)this + 0x2c) + 1;
    **(int **)((int)this + 0x1c) = **(int **)((int)this + 0x1c) + -2;
    if (param_1 != 0xffff) {
      *(ushort *)**(undefined4 **)((int)this + 0x1c) = param_1;
    }
    uVar1 = (uint)param_1;
    if (param_1 == 0xffff) {
      uVar1 = 0;
    }
    return uVar1;
  }
  return CONCAT22((short)((uint)puVar2 >> 0x10),0xffff);
}


// FUNCTION_END

// FUNCTION_START: FUN_10004c10 @ 10004c10