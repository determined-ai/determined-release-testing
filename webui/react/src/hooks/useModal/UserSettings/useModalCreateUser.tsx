import { Form, Input, message, Select, Switch, Table } from 'antd';
import { Button } from 'antd';
import { FormInstance } from 'antd/lib/form/hooks/useForm';
import React, { useCallback, useEffect, useMemo, useState } from 'react';

import { useStore } from 'contexts/Store';
import useFeature from 'hooks/useFeature';
import usePermissions from 'hooks/usePermissions';
import { getUserPermissions, patchUser, postUser, updateGroup } from 'services/api';
import { V1GroupSearchResult } from 'services/api-ts-sdk';
import Icon from 'shared/components/Icon/Icon';
import useModal, { ModalHooks as Hooks } from 'shared/hooks/useModal/useModal';
import { ErrorType } from 'shared/utils/error';
import { DetailedUser, Permission } from 'types';
import handleError from 'utils/error';

export const ADMIN_NAME = 'admin';
export const ADMIN_LABEL = 'Admin';
export const API_SUCCESS_MESSAGE_CREATE = `New user with empty password has been created,
advise user to reset password as soon as possible.`;
export const API_SUCCESS_MESSAGE_EDIT = 'User has been updated';
export const DISPLAY_NAME_NAME = 'displayName';
export const DISPLAY_NAME_LABEL = 'Display Name';
export const MODAL_HEADER_LABEL_CREATE = 'Create User';
export const MODAL_HEADER_LABEL_EDIT = 'Edit User';
export const USER_NAME_NAME = 'username';
export const USER_NAME_LABEL = 'User Name';
export const GROUP_LABEL = 'Add to Groups';
export const GROUP_NAME = 'groups';
export const ROLE_LABEL = 'Roles';
export const ROLE_NAME = 'roles';

interface Props {
  form: FormInstance;
  groups: V1GroupSearchResult[];
  user?: DetailedUser;
  viewOnly?: boolean;
}

interface FormValues {
  ADMIN_NAME: boolean;
  DISPLAY_NAME_NAME?: string;
  GROUP_NAME?: number;
  USER_NAME_NAME: string;
}

const ModalForm: React.FC<Props> = ({ form, user, groups, viewOnly }) => {
  const [ permissions, setPermissions ] = useState<Permission[]>([]);

  const rbacEnabled = useFeature().isOn('rbac');
  const { canGetPermissions, canModifyPermissions } = usePermissions();
  const { knownRoles } = useStore();

  const updatePermissions = useCallback(async () => {
    if (user && canGetPermissions) {
      const viewPermissions = await getUserPermissions({ userId: user.id });
      setPermissions(viewPermissions);
    }
  }, [canGetPermissions, user]);

  useEffect(() => {
    form.setFieldsValue({
      [ADMIN_NAME]: user?.isAdmin,
      [DISPLAY_NAME_NAME]: user?.displayName,
    });
    if (user) {
      updatePermissions();
    }
  }, [ form, updatePermissions, user ]);

  const permissionTableColumn = useMemo(() => {
    const columns = [
      {
        dataIndex: 'name',
        key: 'name',
        title: 'Name',
      },
      {
        dataIndex: 'isGlobal',
        key: 'isGlobal',
        render: (val: boolean) => val ? <Icon name="checkmark" /> : '',
        title: 'Global?',
      },
      {
        dataIndex: 'workspaceOnly',
        key: 'workspaceOnly',
        render: (val: boolean) => val ? <Icon name="checkmark" /> : '',
        title: 'Workspaces?',
      },
    ];
    if (canModifyPermissions && !viewOnly) {
      columns.push({
        dataIndex: 'action',
        key: 'name',
        render: () => <Button danger>Delete</Button>,
        title: '',
      });
    }
    return columns;
  }, [canModifyPermissions, viewOnly]);

  return (
    <Form<FormValues> form={form} labelCol={{ span: 8 }} wrapperCol={{ span: 14 }}>
      <Form.Item
        initialValue={user?.username}
        label={USER_NAME_LABEL}
        name={USER_NAME_NAME}
        required
        rules={[
          {
            message: 'Please type in your username.',
            required: true,
          },
        ]}
        validateTrigger={['onSubmit']}>
        <Input autoFocus disabled={!!user} maxLength={128} placeholder="User Name" />
      </Form.Item>
      <Form.Item label={DISPLAY_NAME_LABEL} name={DISPLAY_NAME_NAME}>
        <Input disabled={viewOnly} maxLength={128} placeholder="Display Name" />
      </Form.Item>
      {!rbacEnabled && (
        <Form.Item label={ADMIN_LABEL} name={ADMIN_NAME} valuePropName="checked">
          <Switch disabled={viewOnly} />
        </Form.Item>
      )}
      {!user && rbacEnabled && (
        <Form.Item label={GROUP_LABEL} name={GROUP_NAME}>
          <Select
            mode="multiple"
            optionFilterProp="children"
            placeholder="Select Groups"
            showSearch>
            {groups.map((u) => (
              <Select.Option key={u.group.groupId} value={u.group.groupId}>
                {u.group.name}
              </Select.Option>
            ))}
          </Select>
        </Form.Item>
      )}
      {rbacEnabled && canModifyPermissions && !viewOnly && (
        <Form.Item label={ROLE_LABEL} name={ROLE_NAME}>
          <Select
          mode="multiple"
          optionFilterProp="children"
          placeholder={'Add Roles'}
          showSearch>
            {knownRoles
            .map((r) => (
              <Select.Option key={r.id} value={r.id}>
                {r.name}
              </Select.Option>
            ))}
          </Select>
        </Form.Item>
      )}
      {!!user && rbacEnabled && canGetPermissions && (
        <Table
          columns={permissionTableColumn}
          dataSource={permissions}
          pagination={{ hideOnSinglePage: true, size: 'small' }}
          rowKey="name"
        />
      )}
    </Form>
  );
};

interface ModalProps {
  groups: V1GroupSearchResult[];
  onClose?: () => void;
  user?: DetailedUser;
}

interface ModalHooks extends Omit<Hooks, 'modalOpen'> {
  modalOpen: (viewOnly?: boolean) => void;
}

const useModalCreateUser = ({ groups, onClose, user }: ModalProps): ModalHooks => {
  const [form] = Form.useForm();
  const { modalOpen: openOrUpdate, ...modalHook } = useModal();

  const handleCancel = useCallback(() => {
    form.resetFields();
  }, [form]);

  const handleOk = useCallback(
    async (viewOnly?: boolean) => {
      if (viewOnly) {
        handleCancel();
        return;
      }
      await form.validateFields();

      const formData = form.getFieldsValue();
      try {
        if (user) {
          await patchUser({ userId: user.id, userParams: formData });
          message.success(API_SUCCESS_MESSAGE_EDIT);
        } else {
          const u = await postUser(formData);
          const uid = u.user?.id;
          if (uid && formData.groups) {
            (formData.groups as number[]).forEach(async (gid) => {
              await updateGroup({ addUsers: [uid], groupId: gid });
            });
          }

          message.success(API_SUCCESS_MESSAGE_CREATE);
        }

        form.resetFields();
        onClose?.();
      } catch (e) {
        message.error(user ? 'Error updating user' : 'Error creating new user');
        handleError(e, { silent: true, type: ErrorType.Input });

        // Re-throw error to prevent modal from getting dismissed.
        throw e;
      }
    },
    [form, onClose, user, handleCancel],
  );

  const modalOpen = useCallback(
    (viewOnly?: boolean) => {
      openOrUpdate({
        closable: true,
        // passing a default brandind due to changes on the initial state
        content: (
          <ModalForm
            form={form}
            groups={groups}
            user={user}
            viewOnly={viewOnly}
          />
        ),
        icon: null,
        okText: viewOnly ? 'Close' : user ? 'Update' : 'Create User',
        onCancel: handleCancel,
        onOk: () => handleOk(viewOnly),
        title: <h5>{user ? MODAL_HEADER_LABEL_EDIT : MODAL_HEADER_LABEL_CREATE}</h5>,
      });
    },
    [form, handleCancel, handleOk, openOrUpdate, user, groups],
  );

  return { modalOpen, ...modalHook };
};

export default useModalCreateUser;
