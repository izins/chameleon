import { useAppContext } from '../context/AppContext';

export const useNotifications = () => {
  const { notifications, unreadCount, markAsRead } = useAppContext();
  return { notifications, unreadCount, markAsRead };
};
