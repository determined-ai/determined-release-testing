/*
Dispatch Centre API

The Dispatch Centre API is the execution layer for the Capsules framework.  It handles all the details of launching and monitoring runtime environments.

API version: 2.7.12
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package launcher

import (
	"encoding/json"
)

// LaunchParameters struct for LaunchParameters
type LaunchParameters struct {
	Mode *string `json:"mode,omitempty"`
	Environment *map[string]string `json:"environment,omitempty"`
	Configuration *map[string]string `json:"configuration,omitempty"`
	Data *[]Data `json:"data,omitempty"`
	Images *map[string]string `json:"images,omitempty"`
	Dependencies *[]string `json:"dependencies,omitempty"`
	Arguments *[]string `json:"arguments,omitempty"`
	Custom *map[string][]string `json:"custom,omitempty"`
	AdditionalPropertiesField *map[string]interface{} `json:"additionalProperties,omitempty"`
}

// NewLaunchParameters instantiates a new LaunchParameters object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewLaunchParameters() *LaunchParameters {
	this := LaunchParameters{}
	return &this
}

// NewLaunchParametersWithDefaults instantiates a new LaunchParameters object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewLaunchParametersWithDefaults() *LaunchParameters {
	this := LaunchParameters{}
	return &this
}

// GetMode returns the Mode field value if set, zero value otherwise.
func (o *LaunchParameters) GetMode() string {
	if o == nil || o.Mode == nil {
		var ret string
		return ret
	}
	return *o.Mode
}

// GetModeOk returns a tuple with the Mode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetModeOk() (*string, bool) {
	if o == nil || o.Mode == nil {
		return nil, false
	}
	return o.Mode, true
}

// HasMode returns a boolean if a field has been set.
func (o *LaunchParameters) HasMode() bool {
	if o != nil && o.Mode != nil {
		return true
	}

	return false
}

// SetMode gets a reference to the given string and assigns it to the Mode field.
func (o *LaunchParameters) SetMode(v string) {
	o.Mode = &v
}

// GetEnvironment returns the Environment field value if set, zero value otherwise.
func (o *LaunchParameters) GetEnvironment() map[string]string {
	if o == nil || o.Environment == nil {
		var ret map[string]string
		return ret
	}
	return *o.Environment
}

// GetEnvironmentOk returns a tuple with the Environment field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetEnvironmentOk() (*map[string]string, bool) {
	if o == nil || o.Environment == nil {
		return nil, false
	}
	return o.Environment, true
}

// HasEnvironment returns a boolean if a field has been set.
func (o *LaunchParameters) HasEnvironment() bool {
	if o != nil && o.Environment != nil {
		return true
	}

	return false
}

// SetEnvironment gets a reference to the given map[string]string and assigns it to the Environment field.
func (o *LaunchParameters) SetEnvironment(v map[string]string) {
	o.Environment = &v
}

// GetConfiguration returns the Configuration field value if set, zero value otherwise.
func (o *LaunchParameters) GetConfiguration() map[string]string {
	if o == nil || o.Configuration == nil {
		var ret map[string]string
		return ret
	}
	return *o.Configuration
}

// GetConfigurationOk returns a tuple with the Configuration field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetConfigurationOk() (*map[string]string, bool) {
	if o == nil || o.Configuration == nil {
		return nil, false
	}
	return o.Configuration, true
}

// HasConfiguration returns a boolean if a field has been set.
func (o *LaunchParameters) HasConfiguration() bool {
	if o != nil && o.Configuration != nil {
		return true
	}

	return false
}

// SetConfiguration gets a reference to the given map[string]string and assigns it to the Configuration field.
func (o *LaunchParameters) SetConfiguration(v map[string]string) {
	o.Configuration = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *LaunchParameters) GetData() []Data {
	if o == nil || o.Data == nil {
		var ret []Data
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetDataOk() (*[]Data, bool) {
	if o == nil || o.Data == nil {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *LaunchParameters) HasData() bool {
	if o != nil && o.Data != nil {
		return true
	}

	return false
}

// SetData gets a reference to the given []Data and assigns it to the Data field.
func (o *LaunchParameters) SetData(v []Data) {
	o.Data = &v
}

// GetImages returns the Images field value if set, zero value otherwise.
func (o *LaunchParameters) GetImages() map[string]string {
	if o == nil || o.Images == nil {
		var ret map[string]string
		return ret
	}
	return *o.Images
}

// GetImagesOk returns a tuple with the Images field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetImagesOk() (*map[string]string, bool) {
	if o == nil || o.Images == nil {
		return nil, false
	}
	return o.Images, true
}

// HasImages returns a boolean if a field has been set.
func (o *LaunchParameters) HasImages() bool {
	if o != nil && o.Images != nil {
		return true
	}

	return false
}

// SetImages gets a reference to the given map[string]string and assigns it to the Images field.
func (o *LaunchParameters) SetImages(v map[string]string) {
	o.Images = &v
}

// GetDependencies returns the Dependencies field value if set, zero value otherwise.
func (o *LaunchParameters) GetDependencies() []string {
	if o == nil || o.Dependencies == nil {
		var ret []string
		return ret
	}
	return *o.Dependencies
}

// GetDependenciesOk returns a tuple with the Dependencies field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetDependenciesOk() (*[]string, bool) {
	if o == nil || o.Dependencies == nil {
		return nil, false
	}
	return o.Dependencies, true
}

// HasDependencies returns a boolean if a field has been set.
func (o *LaunchParameters) HasDependencies() bool {
	if o != nil && o.Dependencies != nil {
		return true
	}

	return false
}

// SetDependencies gets a reference to the given []string and assigns it to the Dependencies field.
func (o *LaunchParameters) SetDependencies(v []string) {
	o.Dependencies = &v
}

// GetArguments returns the Arguments field value if set, zero value otherwise.
func (o *LaunchParameters) GetArguments() []string {
	if o == nil || o.Arguments == nil {
		var ret []string
		return ret
	}
	return *o.Arguments
}

// GetArgumentsOk returns a tuple with the Arguments field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetArgumentsOk() (*[]string, bool) {
	if o == nil || o.Arguments == nil {
		return nil, false
	}
	return o.Arguments, true
}

// HasArguments returns a boolean if a field has been set.
func (o *LaunchParameters) HasArguments() bool {
	if o != nil && o.Arguments != nil {
		return true
	}

	return false
}

// SetArguments gets a reference to the given []string and assigns it to the Arguments field.
func (o *LaunchParameters) SetArguments(v []string) {
	o.Arguments = &v
}

// GetCustom returns the Custom field value if set, zero value otherwise.
func (o *LaunchParameters) GetCustom() map[string][]string {
	if o == nil || o.Custom == nil {
		var ret map[string][]string
		return ret
	}
	return *o.Custom
}

// GetCustomOk returns a tuple with the Custom field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetCustomOk() (*map[string][]string, bool) {
	if o == nil || o.Custom == nil {
		return nil, false
	}
	return o.Custom, true
}

// HasCustom returns a boolean if a field has been set.
func (o *LaunchParameters) HasCustom() bool {
	if o != nil && o.Custom != nil {
		return true
	}

	return false
}

// SetCustom gets a reference to the given map[string][]string and assigns it to the Custom field.
func (o *LaunchParameters) SetCustom(v map[string][]string) {
	o.Custom = &v
}

// GetAdditionalPropertiesField returns the AdditionalPropertiesField field value if set, zero value otherwise.
func (o *LaunchParameters) GetAdditionalPropertiesField() map[string]interface{} {
	if o == nil || o.AdditionalPropertiesField == nil {
		var ret map[string]interface{}
		return ret
	}
	return *o.AdditionalPropertiesField
}

// GetAdditionalPropertiesFieldOk returns a tuple with the AdditionalPropertiesField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *LaunchParameters) GetAdditionalPropertiesFieldOk() (*map[string]interface{}, bool) {
	if o == nil || o.AdditionalPropertiesField == nil {
		return nil, false
	}
	return o.AdditionalPropertiesField, true
}

// HasAdditionalPropertiesField returns a boolean if a field has been set.
func (o *LaunchParameters) HasAdditionalPropertiesField() bool {
	if o != nil && o.AdditionalPropertiesField != nil {
		return true
	}

	return false
}

// SetAdditionalPropertiesField gets a reference to the given map[string]interface{} and assigns it to the AdditionalPropertiesField field.
func (o *LaunchParameters) SetAdditionalPropertiesField(v map[string]interface{}) {
	o.AdditionalPropertiesField = &v
}

func (o LaunchParameters) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Mode != nil {
		toSerialize["mode"] = o.Mode
	}
	if o.Environment != nil {
		toSerialize["environment"] = o.Environment
	}
	if o.Configuration != nil {
		toSerialize["configuration"] = o.Configuration
	}
	if o.Data != nil {
		toSerialize["data"] = o.Data
	}
	if o.Images != nil {
		toSerialize["images"] = o.Images
	}
	if o.Dependencies != nil {
		toSerialize["dependencies"] = o.Dependencies
	}
	if o.Arguments != nil {
		toSerialize["arguments"] = o.Arguments
	}
	if o.Custom != nil {
		toSerialize["custom"] = o.Custom
	}
	if o.AdditionalPropertiesField != nil {
		toSerialize["additionalProperties"] = o.AdditionalPropertiesField
	}
	return json.Marshal(toSerialize)
}

type NullableLaunchParameters struct {
	value *LaunchParameters
	isSet bool
}

func (v NullableLaunchParameters) Get() *LaunchParameters {
	return v.value
}

func (v *NullableLaunchParameters) Set(val *LaunchParameters) {
	v.value = val
	v.isSet = true
}

func (v NullableLaunchParameters) IsSet() bool {
	return v.isSet
}

func (v *NullableLaunchParameters) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableLaunchParameters(val *LaunchParameters) *NullableLaunchParameters {
	return &NullableLaunchParameters{value: val, isSet: true}
}

func (v NullableLaunchParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableLaunchParameters) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

