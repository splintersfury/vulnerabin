void FUN_14000bfe0(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined1 uVar1;
  undefined8 *puVar2;
  char cVar3;
  undefined1 auStack_98 [40];
  HINSTANCE__ local_70 [8];
  char local_50;
  undefined1 local_48;
  longlong local_40 [4];
  undefined1 local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_98;
  puVar2 = (undefined8 *)FUN_14000a2b0(param_1,param_2,param_3);
  local_20 = 0;
  cVar3 = *(char *)(puVar2 + 4) != '\0';
  uVar1 = cVar3;
  if ((bool)cVar3) {
    FUN_14000e750(local_40,puVar2);
    local_20 = cVar3;
    FUN_140009410(local_70,local_40,param_3);
    cVar3 = local_50;
    uVar1 = local_20;
  }
  local_20 = uVar1;
  local_50 = cVar3;
  FUN_14000d470(local_40);
  local_48 = FUN_14000a330((longlong)local_70);
  FUN_14000a600((longlong)local_70);
  if (local_50 != '\0') {
    FUN_140009b30((undefined8 *)local_70);
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000c090 @ 14000c090