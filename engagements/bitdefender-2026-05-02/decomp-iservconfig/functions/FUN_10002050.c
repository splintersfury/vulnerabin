void __thiscall FUN_10002050(void *this,undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  param_1[1] = this;
  return;
}


// FUNCTION_END

// FUNCTION_START: equivalent @ 10002070

/* Library Function - Single Match
    public: virtual bool __thiscall std::error_category::equivalent(int,class std::error_condition
   const &)const 
   
   Library: Visual Studio 2019 Release */

bool __thiscall
std::error_category::equivalent(error_category *this,int param_1,error_condition *param_2)

{
  int *piVar1;
  undefined1 local_c [8];
  
  piVar1 = (int *)(**(code **)(*(int *)this + 0xc))(local_c,param_1);
  if ((*(int *)(piVar1[1] + 4) == *(int *)(*(int *)(param_2 + 4) + 4)) &&
     (*piVar1 == *(int *)param_2)) {
    return true;
  }
  return false;
}


// FUNCTION_END

// FUNCTION_START: equivalent @ 100020b0

/* Library Function - Single Match
    public: virtual bool __thiscall std::error_category::equivalent(class std::error_code const
   &,int)const 
   
   Library: Visual Studio 2019 Release */

bool __thiscall
std::error_category::equivalent(error_category *this,error_code *param_1,int param_2)

{
  if ((*(int *)(this + 4) == *(int *)(*(int *)(param_1 + 4) + 4)) && (*(int *)param_1 == param_2)) {
    return true;
  }
  return false;
}


// FUNCTION_END

// FUNCTION_START: FUN_100020e0 @ 100020e0