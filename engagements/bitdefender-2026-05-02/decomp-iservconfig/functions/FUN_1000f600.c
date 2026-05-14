void __thiscall FUN_1000f600(void *this,char param_1)

{
  void *pvVar1;
  undefined4 *puVar2;
  int local_58 [7];
  uint local_3c [6];
  undefined8 local_24;
  undefined1 local_19;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e9ed;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  switch(param_1) {
  case '\0':
    *(undefined4 *)this = 0;
    break;
  case '\x01':
    local_24 = 0;
    puVar2 = (undefined4 *)operator_new(8);
    local_24 = CONCAT44(puVar2,&local_19);
    local_8 = 0;
    *puVar2 = 0;
    puVar2[1] = 0;
    pvVar1 = operator_new(0x38);
    *(void **)pvVar1 = pvVar1;
    *(void **)((int)pvVar1 + 4) = pvVar1;
    *(void **)((int)pvVar1 + 8) = pvVar1;
    *(undefined2 *)((int)pvVar1 + 0xc) = 0x101;
    *puVar2 = pvVar1;
    goto LAB_1000f68d;
  case '\x02':
    puVar2 = (undefined4 *)operator_new(0xc);
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
    *(undefined4 **)this = puVar2;
    break;
  case '\x03':
    local_24 = 0;
    puVar2 = (undefined4 *)operator_new(0x18);
    local_24 = CONCAT44(puVar2,&local_19);
    local_8 = 1;
    *puVar2 = 0;
    puVar2[4] = 0;
    puVar2[5] = 0xf;
    FUN_10008e70(puVar2,(uint *)&DAT_1005e237,0);
LAB_1000f68d:
    *(undefined4 **)this = puVar2;
    break;
  case '\x04':
    *(undefined1 *)this = 0;
    break;
  case '\x05':
  case '\x06':
    *(undefined4 *)this = 0;
    *(undefined4 *)((int)this + 4) = 0;
    break;
  case '\a':
    *(undefined8 *)this = 0;
    break;
  default:
    *(undefined4 *)this = 0;
    if (param_1 == '\0') {
      FUN_10005690(local_3c,(uint *)"961c151d2e87f2686a955a9be24d316f1362bf21 3.7.0");
      local_8 = 2;
      FUN_1000b150(local_58,local_3c);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_58,&DAT_10067548);
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000f7b0 @ 1000f7b0