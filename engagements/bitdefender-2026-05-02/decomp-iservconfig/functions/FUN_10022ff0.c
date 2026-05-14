undefined1 * __thiscall FUN_10022ff0(void *this,undefined1 *param_1)

{
  undefined1 *puVar1;
  undefined4 uVar2;
  
  puVar1 = *(undefined1 **)((int)this + 0x10);
  if (*(char *)((int)this + 0x14) != '\0') {
    *param_1 = *puVar1;
    uVar2 = *(undefined4 *)(puVar1 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(puVar1 + 8);
    *(undefined4 *)(param_1 + 0xc) = uVar2;
    *puVar1 = 0;
    *(undefined4 *)(puVar1 + 8) = 0;
    *(undefined4 *)(puVar1 + 0xc) = 0;
    return param_1;
  }
  FUN_10011220(param_1,puVar1);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023040 @ 10023040