wchar_t * __thiscall FUN_10002900(void *this,wchar_t *param_1,wchar_t *param_2)

{
  wchar_t wVar1;
  
  if (param_1 != param_2) {
    do {
      wVar1 = __Towlower(*param_1,(_Ctypevec *)((int)this + 8));
      *param_1 = wVar1;
      param_1 = param_1 + 1;
    } while (param_1 != param_2);
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002940 @ 10002940