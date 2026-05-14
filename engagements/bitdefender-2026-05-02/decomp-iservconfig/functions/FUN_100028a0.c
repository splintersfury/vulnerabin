undefined2 * __thiscall
FUN_100028a0(void *this,undefined4 param_1,undefined2 *param_2,undefined2 *param_3)

{
  char cVar1;
  
  if (param_2 != param_3) {
    do {
                    /* WARNING: Load size is inaccurate */
      cVar1 = (**(code **)(*this + 0x10))(param_1,*param_2);
      if (cVar1 == '\0') {
        return param_2;
      }
      param_2 = param_2 + 1;
    } while (param_2 != param_3);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_100028e0 @ 100028e0