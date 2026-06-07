package serial

import (
	"reflect"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

var typedMessageSidecars sync.Map

var typedMessageSidecarBytesType = reflect.TypeOf([]byte(nil))

//converts a proto Message into TypedMessage.
func ToTypedMessage(message proto.Message) *TypedMessage {
	if message == nil {
		return nil
	}
	settings, _ := proto.Marshal(message)
	tm := &TypedMessage{
		Type:  GetMessageType(message),
		Value: settings,
	}
	// Preserve non-proto censhaper sidecars across TypedMessage round-trips.
	if sidecars := collectTypedMessageSidecars(reflect.ValueOf(message), nil); len(sidecars) > 0 {
		for _, s := range sidecars {
			if s != nil {
				typedMessageSidecars.Store(tm, sidecars)
				break
			}
		}
	}
	return tm
}

// GetMessageType returns the name of this proto Message.
func GetMessageType(message proto.Message) string {
	return string(message.ProtoReflect().Descriptor().FullName())
}

// GetInstance creates a new instance of the message with messageType.
func GetInstance(messageType string) (interface{}, error) {
	messageTypeDescriptor := protoreflect.FullName(messageType)
	mType, err := protoregistry.GlobalTypes.FindMessageByName(messageTypeDescriptor)
	if err != nil {
		return nil, err
	}
	return mType.New().Interface(), nil
}

// GetInstance converts current TypedMessage into a proto Message.
func (v *TypedMessage) GetInstance() (proto.Message, error) {
	instance, err := GetInstance(v.Type)
	if err != nil {
		return nil, err
	}
	protoMessage := instance.(proto.Message)
	if err := proto.Unmarshal(v.Value, protoMessage); err != nil {
		return nil, err
	}
	if sidecars, ok := typedMessageSidecars.Load(v); ok {
		index := 0
		restoreTypedMessageSidecars(reflect.ValueOf(protoMessage), sidecars.([][]byte), &index)
	}
	return protoMessage, nil
}

func collectTypedMessageSidecars(v reflect.Value, sidecars [][]byte) [][]byte {
	if !v.IsValid() {
		return sidecars
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return sidecars
		}
		return collectTypedMessageSidecars(v.Elem(), sidecars)
	case reflect.Struct:
		field := v.FieldByName("censhaperSettingsJSON")
		if field.IsValid() && field.Type() == typedMessageSidecarBytesType {
			if field.Len() > 0 {
				sidecars = append(sidecars, append([]byte(nil), field.Bytes()...))
			} else {
				sidecars = append(sidecars, nil)
			}
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			sidecars = collectTypedMessageSidecars(v.Field(i), sidecars)
		}
	case reflect.Slice, reflect.Array:
		if v.Type() == typedMessageSidecarBytesType {
			return sidecars
		}
		for i := 0; i < v.Len(); i++ {
			sidecars = collectTypedMessageSidecars(v.Index(i), sidecars)
		}
	}
	return sidecars
}

func restoreTypedMessageSidecars(v reflect.Value, sidecars [][]byte, index *int) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return
		}
		restoreTypedMessageSidecars(v.Elem(), sidecars, index)
	case reflect.Struct:
		field := v.FieldByName("censhaperSettingsJSON")
		if field.IsValid() && field.Type() == typedMessageSidecarBytesType && field.CanSet() {
			if *index < len(sidecars) && sidecars[*index] != nil {
				field.SetBytes(append([]byte(nil), sidecars[*index]...))
			}
			*index++
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			restoreTypedMessageSidecars(v.Field(i), sidecars, index)
		}
	case reflect.Slice, reflect.Array:
		if v.Type() == typedMessageSidecarBytesType {
			return
		}
		for i := 0; i < v.Len(); i++ {
			restoreTypedMessageSidecars(v.Index(i), sidecars, index)
		}
	}
}
