#include "nan.h"
#include "async.h"
#include "keytar.h"

using keytar::KEYTAR_OP_RESULT;

namespace {

NAN_METHOD(SetPassword) {
  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Parameter 'service' must be a string");
    return;
  }

  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  if (!info[1]->IsString()) {
    Nan::ThrowTypeError("Parameter 'username' must be a string");
    return;
  }

  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  if (!info[2]->IsString()) {
    Nan::ThrowTypeError("Parameter 'password' must be a string");
    return;
  }

  Nan::Utf8String passwordNan(info[2]);
  std::string password(*passwordNan, passwordNan.length());

  SetPasswordWorker* worker = new SetPasswordWorker(
    service,
    username,
    password,
    new Nan::Callback(info[3].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(GetPassword) {
  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Parameter 'service' must be a string");
    return;
  }

  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  if (!info[1]->IsString()) {
    Nan::ThrowTypeError("Parameter 'username' must be a string");
    return;
  }

  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  GetPasswordWorker* worker = new GetPasswordWorker(
    service,
    username,
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(DeletePassword) {
  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Parameter 'service' must be a string");
    return;
  }

  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  if (!info[1]->IsString()) {
    Nan::ThrowTypeError("Parameter 'username' must be a string");
    return;
  }

  Nan::Utf8String usernameNan(info[1]);
  std::string username(*usernameNan, usernameNan.length());

  DeletePasswordWorker* worker = new DeletePasswordWorker(
    service,
    username,
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(FindPassword) {
  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Parameter 'service' must be a string");
    return;
  }

  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  FindPasswordWorker* worker = new FindPasswordWorker(
    service,
    new Nan::Callback(info[1].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(FindCredentials) {
  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Parameter 'service' must be a string");
    return;
  }

  Nan::Utf8String serviceNan(info[0]);
  std::string service(*serviceNan, serviceNan.length());

  FindCredentialsWorker* worker = new FindCredentialsWorker(
    service,
    new Nan::Callback(info[1].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(GetPasswordSync){
  std::string password,error;
  KEYTAR_OP_RESULT result =keytar::GetPassword(*v8::String::Utf8Value(info[0]),
                      *v8::String::Utf8Value(info[1]),&password,&error);
  // if (result == keytar::FAIL_ERROR) {
  //   SetErrorMessage(error.c_str());
  // } else 
  if (result == keytar::FAIL_NONFATAL) {
    info.GetReturnValue().Set(Nan::Null());
  } else {
    info.GetReturnValue().Set(Nan::New(password).ToLocalChecked());
  }
}

void Init(v8::Handle<v8::Object> exports) {
  Nan::SetMethod(exports, "getPassword", GetPassword);
  Nan::SetMethod(exports, "setPassword", SetPassword);
  Nan::SetMethod(exports, "deletePassword", DeletePassword);
  Nan::SetMethod(exports, "findPassword", FindPassword);
  Nan::SetMethod(exports, "findCredentials", FindCredentials);
  Nan::SetMethod(exports, "getPasswordSync",GetPasswordSync);
}

}  // namespace

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(keytar, Init)
#else
NODE_MODULE(keytar, Init)
#endif
